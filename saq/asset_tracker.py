"""Asset tracking functionality helps track assets by hostname for 
the purpose of easily identifying rogue devices or devices without
all of our security tools.

This file contains the database functions and the CLI parser for
interacting with the database.

"""

import argparse
import os
import contextlib
import logging
import enum
import json
import dateutil
import datetime

from typing import Union, List, Dict

from sqlalchemy import create_engine, Boolean, Column, Enum, func, ForeignKey, DateTime, Integer, String, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.exc import IntegrityError

import saq

# security tools we expect to be on our clients
REQUIRE_ALL_TOOLS = []
REQUIRE_ONE_OF_TOOLS = []
try:
    if "asset_tracking" in saq.CONFIG:
        REQUIRE_ALL_TOOLS = saq.CONFIG["asset_tracking"].get("require_all_tools", "").split(",")
        REQUIRE_ONE_OF_TOOLS = saq.CONFIG["asset_tracking"].get("require_one_of_tools", "").split(",")
except AttributeError:
    pass

############
# DATABASE #
############
try:
    DATABASE_PATH = f"{saq.DATA_DIR}/asset_tracking_database.sqlite"
except AttributeError:
    # saq is not initialized, try assumption.
    saq_home = os.environ.get('SAQ_HOME', '/opt/ace')
    DATABASE_PATH = f"{saq_home}/data/asset_tracking_database.sqlite"
    if not os.path.exists(DATABASE_PATH):
        logging.warning(f"ACE is not initialized and an existing asset tracking database was not found")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

Session = sessionmaker(autocommit=False, autoflush=True, bind=engine)

Base = declarative_base()


@contextlib.contextmanager
def get_db_session():
    """Get a database session."""
    db = Session()
    try:
        yield db
    finally:
        db.close()


class Status(enum.Enum):
    """
    Asset Status.

    Can be one of:
        - compliant: Company owned asset, managed by IT, and has ALL security toolsets required for the device type.
        - non_compliant: Company owned asset, not managed by IT and/or missing some or all of the security toolsets required for the device type.
        - unknown: Unable to identify ownership of device with additional research required.
        - rogue: A device NOT KNOWN to be owned by the company with unapproved connectivity within the environment. Detection point and needs to be addressed.

    NOTE: AzureAD device status is used as the authority on company ownership and management of devices.
          However, a device with ALL required security observed authenticating via windows logs will be considered compliant.
    """

    compliant = "compliant"
    non_compliant = "non_compliant"
    unknown = "unknown"
    rogue = "rogue"

    @classmethod
    def has_value(cls, value):
        return value in set(item.value for item in cls)

    @classmethod
    def values(cls):
        return [item.value for item in cls]


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    hostname = Column(String, unique=True, index=True)
    status = Column(Enum(Status), default="unknown")
    insert_date = Column(DateTime, default=datetime.datetime.utcnow)
    last_observed = Column(DateTime, default=None)
    attributes = relationship("Attribute", back_populates="asset")

    def __str__(self):
        insert_date = self.insert_date.strftime("%Y-%m-%d %H:%M:%S")
        last_observed = self.last_observed.strftime("%Y-%m-%d %H:%M:%S") if self.last_observed else self.last_observed
        return f"Asset: ID={self.id}, Hostname={self.hostname}, Status={self.status.name}, Insert Date={insert_date}, Last Observed={last_observed}"

    def to_dict(self):
        return {
            "id": self.id,
            "hostname": self.hostname,
            "status": self.status.value,
            "insert_date": self.insert_date.isoformat(),
            "last_observed": self.last_observed_time.isoformat() if self.last_observed else self.last_observed,
        }

    @property
    def last_observed_time(self):
        # database does not know `last_observed` is UTC
        if not self.last_observed:
            return None
        return self.last_observed.replace(tzinfo=dateutil.tz.UTC)


class AttributeStatus(enum.Enum):
    good = "good"
    missing = "missing"

    @classmethod
    def has_value(cls, value):
        return value in set(item.value for item in cls)

    @classmethod
    def values(cls):
        return [item.value for item in cls]


class Attribute(Base):
    """Something we know about the asset, like a tool we have on it.

    NOTE: These are meant to be temporary and should be expired after a time period.
    """

    __tablename__ = "asset_attributes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    name = Column(String, index=True)
    last_observed = Column(DateTime, default=datetime.datetime.utcnow)
    detail = Column(String)  # store log that proves it?
    status = Column(Enum(AttributeStatus), default="good")
    asset = relationship("Asset", back_populates="attributes")

    def __str__(self):
        last_observed = self.last_observed.strftime("%Y-%m-%d %H:%M:%S")
        return f"Attribute ID={self.id}: Asset ID={self.asset_id} has {self.name} with {self.status}, Last Observed={last_observed}, Detail Length={len(self.detail)}"

    def to_dict(self):
        detail = self.detail
        try:
            detail = json.loads(self.detail)
        except json.decoder.JSONDecodeError:
            pass

        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "attribute_name": self.name,
            "status": self.status.value,
            "last_observed": self.last_observed.isoformat(),
            "detail": detail,
        }

    @property
    def last_observed_time(self):
        return self.last_observed.replace(tzinfo=dateutil.tz.UTC)


## Helper class ##
class EnrichedAsset:
    """A helper class for loading assets with their attributes."""

    # TODO have this class update status based on time and attributes
    def __init__(self, asset: Asset):
        self.asset = asset
        self.attributes = self.get_attributes()

    def get_attributes(self):
        with get_db_session() as session:
            return get_asset_attributes(session, self.asset)

    def evaluate_asset(self):
        with get_db_session() as session:
            # make the asset persistent in this session to updates are reflected
            self.asset = get_asset_by_id(session, self.asset.id)
            evalute_asset_attributes_and_update_status(session, self.asset)

    def __str__(self):
        self.evaluate_asset()
        txt = f"{self.asset}"
        for attribute in self.attributes:
            txt += "\n\t" + "\u21B3" + f" {attribute}"
        return txt

    def to_dict(self):
        self.evaluate_asset()
        data = self.asset.to_dict()
        data["attributes"] = [attribute.to_dict() for attribute in self.attributes]
        return data


## Database helper functions ##
def create_asset(db: Session, hostname: str, status: str = Status.unknown.value, last_observed=None):
    if not Status.has_value(status):
        logging.error(f"{status} is not a valid asset status.")
        return False
    asset = Asset(hostname=hostname.upper(), status=status, last_observed=last_observed)
    db.add(asset)
    try:
        db.commit()
    except IntegrityError as e:
        logging.error(f"failed to create asset by hostname={hostname}: {e}")
        return False
    db.refresh(asset)
    return asset


def update_asset_status(db: Session, asset: Union[Asset, int, str], status):
    asset = _get_asset_by_unknown(db, asset)
    if not asset:
        return asset
    asset.status = status
    db.commit()
    db.refresh(asset)
    return asset


def update_asset_observation_time(db: Session, asset: Union[Asset, int, str], observed_time: datetime.datetime):
    asset = _get_asset_by_unknown(db, asset)
    if not asset:
        return asset
    asset.last_observed = observed_time
    db.commit()
    db.refresh(asset)
    return asset


def delete_asset(db: Session, asset: Union[Asset, int, str]):
    asset = _get_asset_by_unknown(db, asset)
    if not asset:
        return asset
    # also delete all asset attributes
    for attribute in get_asset_attributes(db, asset):
        db.delete(attribute)
    db.delete(asset)
    db.commit()
    return True


def get_asset_by_id(db: Session, asset_id):
    return db.query(Asset).filter(Asset.id == asset_id).first()


def get_asset_by_name(db: Session, asset_name):
    # case-insensitive lookup by forcing uppercase
    return db.query(Asset).filter(func.upper(Asset.hostname) == asset_name.upper()).first()


def get_all_assets(db: Session):
    return db.query(Asset).all()


def _get_asset_by_unknown(db: Session, asset: Union[Asset, int, str]):
    if isinstance(asset, Asset):
        return asset
    if isinstance(asset, int):
        return get_asset_by_id(db, asset)
    if isinstance(asset, str):
        return get_asset_by_name(db, asset)
    return None


def _get_asset_id(db: Session, asset: Union[Asset, int, str]):
    if isinstance(asset, Asset):
        return asset.id
    if isinstance(asset, int):
        return asset
    if isinstance(asset, str):
        return get_asset_by_name(db, asset).id
    return None


def assign_attribute(
    db: Session,
    asset: Union[Asset, int, str],
    attribute_name: str,
    last_observed: datetime.datetime,
    detail: str,
    status: AttributeStatus = AttributeStatus.good,
):
    """Assign a new attribute to an asset by asset ID."""
    asset_id = _get_asset_id(db, asset)
    if not asset_id:
        logging.warning(f"no asset found for {asset}")
        return False
    attribute = Attribute(
        asset_id=asset_id, name=attribute_name, last_observed=last_observed, detail=detail, status=status
    )
    db.add(attribute)
    db.commit()
    db.refresh(attribute)
    return attribute


def get_attribute_by_name(db: Session, asset: Union[Asset, int, str], attribute_name: str):
    asset_id = _get_asset_id(db, asset)
    query = db.query(Attribute).filter(Attribute.asset_id == asset_id).filter(Attribute.name == attribute_name)
    if not query.count():
        logging.debug(f"no attribute by name={attribute_name} for asset id={asset_id} found.")
        return None
    attribute = query.first()
    return attribute


def get_attribute_by_id(db: Session, attribute_id: int):
    return db.query(Attribute).filter(Attribute.id == attribute_id).first()


def get_asset_attributes(db: Session, asset: Union[Asset, int, str]):
    asset_id = _get_asset_id(db, asset)
    if not asset_id:
        return None
    return db.query(Attribute).filter(Attribute.asset_id == asset_id).all()


def get_unique_attribute_names(db: Session):
    return [n[0] for n in db.query(Attribute.name).distinct().all()]


def update_attribute(
    db: Session,
    attribute: Union[Attribute, int],
    last_observed: datetime.datetime = None,
    detail: str = None,
    status: AttributeStatus = None,
):
    """Update observed time and/or detail for an existing attribute by asset ID and attribute name."""
    if isinstance(attribute, int):
        attribute = get_attribute_by_id(db, attribute)
    if not attribute:
        return attribute
    if last_observed is not None:
        attribute.last_observed = last_observed
    if detail is not None:
        attribute.detail = detail
    if isinstance(status, AttributeStatus):
        attribute.status = status
    db.commit()
    db.refresh(attribute)
    return attribute


def remove_attribute(db: Session, attribute: Attribute):
    """Remove an attribute from this asset."""
    db.delete(attribute)
    db.commit()
    return True


def create_tables():
    """Create the database tables."""
    Base.metadata.create_all(bind=engine)


try:
    create_tables()
except Exception as e:
    logging.warning(f"problem creating tables: {e}")

# END DATABASE functions #

####################################
# Begin Data Maintenance Functions #
####################################
def time_since_observation(item: Union[Attribute, Asset]) -> datetime.timedelta:
    """Return the time since last observation."""
    if not item.last_observed:
        return None

    now = datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.UTC)
    return now - item.last_observed_time


def evaluate_age_of_all_attributes_and_update_status(
    session: Session, attributes: List[Attribute], max_attribute_absence=4
):
    """Update attribute status to `missing` if attribute hasn't been seen in `max_attribute_absence` days."""
    for attribute in attributes:
        elapsed_time = time_since_observation(attribute)
        logging.debug(f"elapsed time since attribute({attribute.id}) checked in: {elapsed_time}")
        if elapsed_time > datetime.timedelta(days=max_attribute_absence):
            # update status to missing
            logging.info(f"updating {attribute.id}:{attribute.name} as missing for asset={attribute.asset_id}")
            update_attribute(session, attribute, status=AttributeStatus.missing)
        elif attribute.status == AttributeStatus.missing:
            logging.info(f"updating {attribute.id}:{attribute.name} as good for asset={attribute.asset_id}")
            update_attribute(session, attribute, status=AttributeStatus.good)
    return attributes


def evalute_asset_attributes_and_update_status(
    session: Session, asset: Union[Asset, int, str], evalute_attribute_status=True
):
    """Execute the logic to change asset status.

    Take into consideration:
        1. Required security tools
        2. Observation age
    """
    if "asset_tracking" in saq.CONFIG:
        REQUIRE_ALL_TOOLS = saq.CONFIG["asset_tracking"].get("require_all_tools", "").split(",")
        REQUIRE_ONE_OF_TOOLS = saq.CONFIG["asset_tracking"].get("require_one_of_tools", "").split(",")
        max_attribute_absence = saq.CONFIG["asset_tracking"].getint("max_attribute_absence_days", 4)
        max_asset_absence_days = saq.CONFIG["asset_tracking"].getint("max_asset_absence_days", 6)

    # check age of device and update to unknown, if not unknown or rogue
    elapsed_time = time_since_observation(asset)
    logging.debug(f"elapsed time since asset({asset.id}) checked in: {elapsed_time}")
    if elapsed_time > datetime.timedelta(days=max_asset_absence_days):
        if asset.status not in [Status.unknown, Status.rogue]:
            logging.info(
                f"{asset.hostname} hasn't been observed in '{elapsed_time}' - updating status from {asset.status.value} to unknown."
            )
            update_asset_status(session, asset, Status.unknown)
            return
        logging.info(
            f"{asset.hostname} hasn't been observed in '{elapsed_time}' and remains in {asset.status.value} state."
        )
        return

    attributes = get_asset_attributes(session, asset)
    if evalute_attribute_status:
        logging.info(f"evaluating attribute statuses for {asset.hostname}")
        attributes = evaluate_age_of_all_attributes_and_update_status(
            session, attributes, max_attribute_absence=max_attribute_absence
        )

    attribute_names = [a.name.lower() for a in attributes if a.status == AttributeStatus.good]
    has_all_of_these_security_tools = all(tool.lower() in attribute_names for tool in REQUIRE_ALL_TOOLS)
    has_any_of_these_security_tools = any(tool.lower() in attribute_names for tool in REQUIRE_ONE_OF_TOOLS)

    if not has_all_of_these_security_tools and not has_any_of_these_security_tools:
        # devices with NO security tools.
        if asset.status == Status.rogue:
            logging.info(f"{asset.hostname} has zero security tools and is classified as a rogue device.")
            # leave the status as rogue, which would mean the asset was discovered as rogue and STILL doesn't have any security tools.
            # This should mean that the device was observed in logs (windows authentication, for instance) indicating a level of risk
            # via unapproved connectivity within the environment.
            return
        if asset.status != Status.non_compliant:
            update_asset_status(session, asset, Status.non_compliant.value)
        logging.info(f"{asset.hostname} has zero security tools.")

    elif has_all_of_these_security_tools and has_any_of_these_security_tools:
        # compliant
        update_asset_status(session, asset, Status.compliant.value)

    else:
        # Device with some security tools.
        update_asset_status(session, asset, Status.non_compliant.value)

    return


def evaluate_status_of_all_assets(session: Session, evalute_attribute_status=True):
    """Iterate all assets and update status.

    Update to `missing` if attribute hasn't been seen in `max_attribute_absence` days.
    Else, continue to evaluate attributes and reflect asset status accordingly.
    """

    for asset in get_all_assets(session):
        logging.info(f"evaluating attributes to set {asset.hostname} status as complant or non-compliant.")
        evalute_asset_attributes_and_update_status(session, asset, evalute_attribute_status=evalute_attribute_status)


DEFAULT_DATA_FIELD_MAP = {
    "hostname": ["hostname", "name", "displayName"],
    "last_observed": ["last_observed", "event_time", "_time", "approximateLastSignInDateTime", "last_contact_time"],
    "detail": ["attribute_detail"],  # If None, uses the event itself.
}


def asset_data_parser(
    data: List[Dict], field_map=DEFAULT_DATA_FIELD_MAP, attribute_name=None, evalute_attribute_status=False
):
    """Parse data and update the tracking database.

    All data should enter the database through this function.

    The attribute_name is the source identifier of this asset data.

    The following fields are expected to exist in the data:
        - name or hostname
        - _time or event_time
        - _raw or detail or the data itself is used
    """
    logging.info(f"parsing {len(data)} data item for asset tracking...")
    for event in data:

        if attribute_name is None:
            attribute_name = event.get("attribute_name")
            if not attribute_name:
                logging.error(f"no attribute_name supplied... meaningless...")
                continue

        for hostname_key in field_map.get("hostname", []):
            hostname = event.get(hostname_key)
            if hostname:
                hostname = hostname[hostname.rfind("\\") + 1 :] if "\\" in hostname else hostname
                break

        for detail_key in field_map.get("detail", []):
            detail = event.get(detail_key)
            if detail:
                break
        if not detail:
            detail = event  # default
        try:
            detail = json.dumps(detail)
        except:
            detail = str(detail)

        for time_key in field_map.get("last_observed", []):
            observed_time = event.get(time_key)
            if observed_time:
                break
        if not observed_time:
            logging.error(f"failed to get observation time ... ")
            continue

        if not isinstance(observed_time, datetime.datetime):
            try:
                observed_time = dateutil.parser.isoparse(observed_time)
            except Exception as e:
                logging.debug(f"failed to parse time: {e}")
                pass
            try:
                observed_time = dateutil.parser.parse(observed_time)
            except Exception as e:
                logging.debug(f"failed to parse time: {e}")
                pass
            if not isinstance(observed_time, datetime.datetime):
                logging.error(f"failed to parse observation time: {observed_time}")
                continue

        with get_db_session() as session:
            # get or create the asset
            asset = get_asset_by_name(session, hostname)
            if asset:
                logging.info(f"Found existing {asset}")
            else:
                asset = create_asset(session, hostname, last_observed=observed_time)
                if not asset:
                    logging.error(f"failed to create {asset}")
                    continue
                logging.info(f"Created new {asset}")

            if not asset.last_observed_time or (observed_time and observed_time > asset.last_observed_time):
                logging.info(f"updating observation time.")
                update_asset_observation_time(session, asset, observed_time)

            # does this attribute already exist?
            attribute = get_attribute_by_name(session, asset, attribute_name)
            if attribute:
                # is our current data newer?
                if observed_time > attribute.last_observed_time:
                    # update the attribute and continue
                    attribute = update_attribute(session, attribute, observed_time, detail)
                    if not attribute:
                        logging.error(f"failed to update attribute for unknown reasons.")
                        continue
                    logging.info(f"updated {attribute}")
                else:
                    logging.info(f"not updating attribute because its data appears older than our current attribute")
                    continue
            else:
                # create/assign the attribute
                attribute = assign_attribute(session, asset, attribute_name, observed_time, detail)
                if not attribute:
                    logging.error(f"failed to create attribute for unknown reasons.")
                    continue
                logging.info(f"assigned {attribute}")

            # If here, something changed; update the assets status as needed.
            evalute_asset_attributes_and_update_status(
                session, asset, evalute_attribute_status=evalute_attribute_status
            )


def load_asset_data_from_json_file(file_path: str):
    if not os.path.exists:
        logging.error(f"{file_path} not found.")
        return False
    data = None
    with open(file_path, "r") as fp:
        data = json.load(fp)

    return data


def export_database_to_json_report(session: Session):
    # Make columns like: name, status, last_seen, attribute, attribute
    # and then set last_seen for the attribute or None if none.
    import datetime

    data = []
    for asset in get_all_assets(session):
        if asset.hostname.endswith("$"):
            delete_asset(session, asset)
            continue
        asset_data = asset.to_dict()
        for attribute in get_asset_attributes(session, asset):
            asset_data[attribute.name] = (
                attribute.last_observed.strftime("%Y-%m-%d %H:%M:%S")
                if attribute.last_observed
                else attribute.last_observed
            )
        data.append(asset_data)

    now = datetime.datetime.now().replace(microsecond=0).isoformat()
    with open(f"asset_tracking_{now}.json", "w") as f:
        f.write(json.dumps(data, default=str))

    return True


#######################
# Begin CLI functions #
#######################
def build_parser(parser: argparse.ArgumentParser):
    """Build the CLI Argument parser."""

    parser.add_argument("-l", "--list-assets", action="store_true", help="List ALL(!) assets.")
    parser.add_argument("--delete-asset", action="store", default=None, help="Delete an asset by name.")
    parser.add_argument(
        "-r", "--json", dest="raw_results", action="store_true", help="return results in their raw json format"
    )
    parser.add_argument(
        "--from-stdin", action="store_true", help="Inspect each IP in a list of IP addresses passed to STDIN"
    )
    parser.add_argument(
        "-a",
        "--asset-name",
        action="store",
        help="The hostname of an asset to work with. Default returns all asset information.",
    )
    parser.add_argument(
        "-us",
        "--update-asset-status",
        action="store",
        choices=Status.values(),
        help="Update asset status. Use with `-a`.",
    )
    parser.add_argument(
        "-rs", "--refresh-asset-statuses", action="store_true", help="Iterate all assets and evaluate status."
    )
    parser.add_argument(
        "--export-database", action="store_true", help="Export database to JSON file that can be converted to CSV."
    )
    subparsers = parser.add_subparsers(dest="at_command")

    attribute_parser = subparsers.add_parser("attribute", help="Interact with asset attributes.")
    attribute_parser.add_argument(
        "attribute_name", action="store", help="The name of the attribute to assign or work with."
    )
    attribute_parser.add_argument(
        "--delete-attribute", action="store_true", help="delete the resulting attribute from the asset."
    )
    attribute_parser.add_argument(
        "-d", "--attribute-detail", action="store", default=None, help="detail about this asset attribute."
    )
    attribute_parser.add_argument(
        "-t",
        "--last-observed-time",
        action="store",
        help="Last time this attribute was observed to be true.  Format:'Y-m-d H:M:S' OR 'Y-m-dTH:M:S' UTC",
    )

    import_parser = subparsers.add_parser("import-data", help="Import asset data to update the tracking database with.")
    import_parser.add_argument("json_path", action="store", help="Path to the data (which should be in JSON format).")
    import_parser.add_argument(
        "-s",
        "--source-name",
        action="store",
        required=True,
        help="The name of the data source IS the attribute name that gets assigned to the asset.",
    )

    unique_attribute_names = []
    with get_db_session() as session:
        results = session.query(Attribute.name).distinct().all()
        unique_attribute_names = [r[0] for r in results]

    filter_parser = subparsers.add_parser("filter", help="Filter the asset tracking database.")
    filter_parser.add_argument(
        "-r", "--json", dest="raw_results", action="store_true", help="return results in their raw json format"
    )
    filter_parser.add_argument("--enrich", action="store_true", help="Enrich asset results with their attributes.")
    filter_parser.add_argument(
        "-s",
        "--asset-status",
        choices=Status.values(),
        action="append",
        default=None,
        help="Get assets with this status",
    )
    filter_parser.add_argument(
        "-ns",
        "--not-asset-status",
        choices=Status.values(),
        action="append",
        default=None,
        help="Get assets that do NOT have this status.",
    )
    filter_parser.add_argument(
        "-as",
        "--attribute-status",
        choices=AttributeStatus.values(),
        action="store",
        default=None,
        help="Filter attributes by this status.",
    )
    # filter_parser.add_argument(
    #    '-nas', '--not-attribute-status', choices=AttributeStatus.values(), action='store', default=None,
    #    help="Filter for attributes that DO NOT have this status."
    # )
    filter_parser.add_argument(
        "-an",
        "--attribute-name",
        action="append",
        choices=unique_attribute_names,
        default=[],
        help="Filter by assets that have an attribute by this name.",
    )
    filter_parser.add_argument(
        "-nan",
        "--not-attribute-name",
        action="append",
        default=[],
        choices=unique_attribute_names,
        help="Filter by assets that DO NOT have an attribute by this name.",
    )


def execute_arguments(args: argparse.Namespace):

    if args.list_assets:
        with get_db_session() as session:
            assets = get_all_assets(session)
        for asset in assets:
            print(asset)
    elif args.delete_asset:
        with get_db_session() as session:
            asset = get_asset_by_name(session, args.delete_asset)
            delete_asset(session, asset)
    elif args.export_database:
        with get_db_session() as session:
            return export_database_to_json_report(session)
    elif args.update_asset_status:
        if not args.asset_name:
            logging.error(f"must also pass asset hostname to work with using `-a` option.")
            return False
        with get_db_session() as session:
            asset = update_asset_status(session, args.asset_name, args.update_asset_status)
            print(asset)
    elif args.at_command == "attribute":
        if not args.asset_name:
            logging.error(f"Asset name must be specified with the `-a` option.")
            return False

        if args.delete_attribute:
            # delete the attribute, if it exists
            with get_db_session() as session:
                attribute = get_attribute_by_name(session, args.asset_name, args.attribute_name)
                if attribute:
                    return remove_attribute(session, attribute)

        # format datetimes as needed
        format_string = "%Y-%m-%d %H:%M:%S"
        if args.last_observed_time and "T" in args.last_observed_time:
            format_string = "%Y-%m-%dT%H:%M:%S"
        last_observed_time = (
            datetime.datetime.strptime(args.last_observed_time, format_string)
            if args.last_observed_time
            else args.last_observed_time
        )
        if not last_observed_time:
            last_observed_time = datetime.datetime.utcnow()

        if not args.last_observed_time and not args.attribute_detail:
            # check is attribute already exists and return it.
            with get_db_session() as session:
                attribute = get_attribute_by_name(session, args.asset_name, args.attribute_name)
                if attribute:
                    if args.raw_results:
                        print(json.dumps(attribute.to_dict(), indent=2))
                    print(f"Found existing: {attribute}")
                    return True
                else:  # if it does not exist, create it.
                    logging.warning(
                        f"No attribute exists by this name and for this asset. To create this attribute, pass attribute detail with the `-d` option."
                    )
                    return attribute
        else:
            # we are either creating or updating
            with get_db_session() as session:
                attribute = get_attribute_by_name(session, args.asset_name, args.attribute_name)
                if attribute:
                    attribute = update_attribute(session, attribute, last_observed_time, args.attribute_detail)
                    print(f"Updated existing attribute: {attribute}")
                    return attribute
                attribute = assign_attribute(
                    session, args.asset_name, args.attribute_name, last_observed_time, args.attribute_detail
                )
                print(f"Created: {attribute}")
                return attribute
    elif args.asset_name:
        with get_db_session() as session:
            asset = get_asset_by_name(session, args.asset_name)
            if asset:
                enriched_asset = EnrichedAsset(asset)
                if args.raw_results:
                    print(json.dumps(enriched_asset.to_dict(), indent=2))
                    return
                print(f"found:\n  {enriched_asset}")
                return
    elif args.at_command == "import-data":
        data = load_asset_data_from_json_file(args.json_path)
        if not data:
            logging.error(f"no data loaded!")
            return False
        asset_data_parser(data, attribute_name=args.source_name)
    elif args.at_command == "filter":
        with get_db_session() as session:
            # outerjoin or join?
            # query = session.query(Asset).outerjoin(Attribute).filter(Asset.id == Attribute.asset_id)
            # query = session.query(Attribute.asset_id)
            # query = session.query(Asset, Attribute.name).outerjoin(Attribute).group_by(Attribute.asset_id)#
            # query = session.query(Asset, func.group_concat(Attribute.name.distinct()).label('Attributes')).outerjoin(Attribute).filter(Asset.id == Attribute.asset_id)
            query = (
                session.query(Asset, func.group_concat(Attribute.name.distinct()).label("AttributeNames"))
                .join(Attribute)
                .group_by(Attribute.asset_id)
            )

            if args.asset_status:
                # query = query.filter(Asset.status == args.asset_status)
                query = query.filter(Asset.status.in_(args.asset_status))
            if args.not_asset_status:
                query = query.filter(~Asset.status.in_(args.not_asset_status))
                # if args.asset_status == args.not_asset_status:
                #    logging.error(f"your filter doesn't make any sense: {args.asset_status} and NOT {args.not_asset_status}?!")
                #    return False
                # query = query.filter(Asset.status != args.not_asset_status)

            if args.attribute_status:
                query = query.filter(Attribute.status == args.attribute_status)

            # if args.attribute_name:
            #    query = query.filter(Attribute.name.in_(args.attribute_name))
            # for an in args.attribute_name:
            #    query = query.filter(Attribute.name == an)

            # if args.not_attribute_name:
            #    query = query.filter(~Attribute.name.in_(args.not_attribute_name))

            logging.debug(f"Constructed this query: {query}")

            results = query.all()
            if not results:
                return None

            assets = []
            # HACK filter because I was in a hurry and *sqlalchemy*
            if args.attribute_name and args.not_attribute_name:
                assets = [
                    a[0]
                    for a in results
                    if all(an in a[1].split(",") for an in args.attribute_name)
                    and not any(an in a[1].split(",") for an in args.not_attribute_name)
                ]
            elif args.attribute_name:
                assets = [a[0] for a in results if all(an in a[1].split(",") for an in args.attribute_name)]
            elif args.not_attribute_name:
                assets = [a[0] for a in results if not any(an in a[1].split(",") for an in args.not_attribute_name)]
            else:
                assets = [a[0] for a in results]

        if args.raw_results:
            if args.enrich:
                assets = [EnrichedAsset(r).to_dict() for r in assets]
            else:
                assets = [r.to_dict() for r in assets]
            print(json.dumps(assets))
            return
        for asset in assets:
            if args.enrich:
                print(EnrichedAsset(asset))
            else:
                print(asset)
    elif args.refresh_asset_statuses:
        with get_db_session() as session:
            evaluate_status_of_all_assets(session)

    return


'''
if __name__ == '__main__':
    """A CLI entry point."""

    # configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Asset tracker")
    build_parser(parser)
    args = parser.parse_args(args)

    execute_arguments(args)
'''

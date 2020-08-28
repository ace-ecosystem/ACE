"""Functions that are helpful to other metric funcitons."""

import io
import os
import logging
import pymysql

import datetime

import pandas as pd
from typing import Mapping, List, Tuple

from .alerts import FRIENDLY_STAT_NAME_MAP

CompanyID = int
CompanyName = str
CompanyMap = Mapping[CompanyID, CompanyName]

def get_companies(con: pymysql.connections.Connection) -> CompanyMap:
    """Query the database for all companies.

    Args:
        con: a pymysql database connectable

    Returns:
        A dict of companies like so:
          {company_id: 'company_name'}, ..
    """

    # apply company selection by name
    companies = {}
    cursor = con.cursor()
    cursor.execute("select * from company")
    for c_id,c_name in cursor.fetchall():
        companies[c_id] = c_name
    return companies

def apply_company_selection_to_query(query: str, company_ids: list, selected_companies: list) -> str:
    """Update a metric SQL query to select where companies.

    Args:
        query: An ACE DB query structered for reduction by company ID.
          Such a query should have two "{}" back to back, like: {}{}
        company_ids: list of all valid company IDs
        selected_companies: A list of companies to select alerts for, by name.
          If the list is empty, all alerts are selected.

    Returns:
        An updated SQL query string.

    """
    return query.format(' AND ' if company_ids else '', '( ' + ' OR '.join(['company.name=%s' for company in selected_companies]) +') ' if company_ids else '')

def export_dataframes_to_xlsx(tables: List[pd.DataFrame]) -> Tuple[str, bytes]:
    """Export tables to xlsx bytes.

    Write the bytes to a file to send the bytes wherever.

    Args:
        tables: A list of pd.DataFrames

    Returns:
        A tuple with recommended filename and the file bytes
    """

    time_stamp = str(datetime.datetime.now().timestamp())
    time_stamp = time_stamp[:time_stamp.rfind('.')]
    
    filename = f"ACE_metrics_{time_stamp}.xlsx"

    tab_names = []
    tab_name_map = {}
    table_tab_map = {}
    # sanitize and make tab name map
    for table in tables:
        if table.name:
            table_name = table.name.strip()
        else:
            logging.warning("metric table has no name.")
            table_name = f"No name - {time_stamp}"
        clean_table_name = table_name

        # map the friendly names back to their key name
        for stat_key,stat_name in FRIENDLY_STAT_NAME_MAP.items():
            if stat_name in clean_table_name:
                clean_table_name = clean_table_name.replace(stat_name, stat_key)

        # remove any openpyxl.workbook.child.INVALID_TITLE_REGEX
        _invalid_title_chars = ["\\", "*", "?", ":", "/", "[", "]"]
        for invalid_char in _invalid_title_chars:
            clean_table_name = clean_table_name.replace(invalid_char, '-')

        # try to clean up alert_type names
        name_parts = clean_table_name.split(' - ')
        if name_parts:
            _tmp_name = ""
            for part in name_parts[:-1]:
                _tmp_name += f"{part[0].upper()}-"
            clean_table_name = f"{_tmp_name}{name_parts[-1]}"

        # openpyxl guidance to keep names to 31 chars or less
        if len(clean_table_name) > 31:
            clean_table_name = clean_table_name[:31]

        if clean_table_name in tab_names:
            logging.warning(f"name collision for {clean_table_name}")
            # 30 char collision name
            clean_table_name = f"Collision - {datetime.datetime.now().timestamp()}"

        tab_names.append(clean_table_name)

        logging.info(f"changed table name from '{table_name}' to '{clean_table_name}'")
        # will add this helpful info to the excel sheet
        tab_name_map[clean_table_name] = table_name
        table_tab_map[clean_table_name] = table

    xlsx_bytes = io.BytesIO()
    writer = pd.ExcelWriter(xlsx_bytes)
    # write the tab name map first
    tab_name_map_df = pd.DataFrame.from_dict(tab_name_map,
                                            orient='index',
                                            columns=['ACE Data Table Name'])
    tab_name_map_df.index.names = ['Tab Name']
    tab_name_map_df.to_excel(writer, "Tab Name Map")
    for name, table in table_tab_map.items():
        try:
            table.to_excel(writer, name)
        except Exception as e:
            logging.error(f"failed to write table: {e}")

    writer.close()
    xlsx_bytes.seek(0)
    filebytes = xlsx_bytes.read()
    xlsx_bytes.close()

    return filename, filebytes
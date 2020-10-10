# vim: sw=4:ts=4:et:cc=120
import os.path

from saq.constants import *
from saq.observables import create_observable

from saq.modules.snort import (
        _create_signature_key,
        build_signature_db, 
        extract_signature,
        is_signature_db_stale,
        lock_signature_db,
        AlreadyLockedException,
        KEY_SURICATA_RULES_MTIME,
        KEY_SURICATA_RULES_LOCK,)

import fakeredis
import pytest

rule_1 = """alert ip $HOME_NET any -> [109.196.130.50,151.13.184.200] any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:5818; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Shadowserver, signature_severity Major, created_at 2012_05_04, updated_at 2020_08_07;)"""
rule_2 = """alert ip $HOME_NET any -> [154.35.64.107,154.35.64.18] any (msg:"ET CNC Shadowserver Reported CnC Server IP group 2"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404001; rev:5818; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Shadowserver, signature_severity Major, created_at 2012_05_04, updated_at 2020_08_07;)"""
rule_data = '\n'.join([rule_1, rule_2])

keys = [ _create_signature_key(sig, rev) for sig, rev in [ 
    ('2404000', '5818'),
    ('2404001', '5818'),] ]

@pytest.fixture(scope="function")
def redis_connection():
    return fakeredis.FakeStrictRedis(decode_responses=True, encoding='utf-8')

@pytest.fixture
def sig_path(tmp_path):
    result = str(tmp_path / 'temp.rules')
    with open(result, 'w') as fp:
        fp.write(rule_data)

    return result

@pytest.fixture
def sig_db(sig_path, redis_connection):
    return build_signature_db(sig_path, get_redis_connection=lambda: redis_connection)

@pytest.mark.unit
def test_lock_signature_db(sig_db):
    assert KEY_SURICATA_RULES_LOCK not in sig_db

    with lock_signature_db(get_redis_connection=lambda: sig_db) as lock_uuid:
        assert lock_uuid
        with pytest.raises(AlreadyLockedException):
            with lock_signature_db(get_redis_connection=lambda: sig_db) as invalid_lock_uuid:
                assert invalid_lock_uuid is None # not called

    assert KEY_SURICATA_RULES_LOCK not in sig_db

@pytest.mark.unit
def test_build_signature_db(sig_path, sig_db):
    assert sig_db
    assert sig_db[keys[0]] == rule_1
    assert sig_db[keys[1]] == rule_2
    assert int(os.path.getmtime(sig_path)) == int(sig_db[KEY_SURICATA_RULES_MTIME])
    assert not is_signature_db_stale(sig_path, get_redis_connection=lambda: sig_db)

@pytest.mark.unit
def test_extract_signature(sig_db):
    assert extract_signature('2404000', '5818', get_redis_connection=lambda: sig_db) == rule_1
    assert extract_signature('2404001', '5818', get_redis_connection=lambda: sig_db) == rule_2
    assert extract_signature('2404002', '5818', get_redis_connection=lambda: sig_db) is None

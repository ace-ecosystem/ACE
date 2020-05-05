# vim: sw=4:ts=4:et:cc=120

import unittest

import saq
from saq.integration import integration_enabled
from saq.submission import Submission
from saq.test import *
from saq.util import *

from saq.collectors.falcon import *

metadata ={ KEY_EVENT_CREATION_TIME: 1587665314 * 1000 } 
event = {
   "PatternDispositionDescription" : "Prevention, process was blocked from execution.",
   "ComputerName" : "HOSTNAME",
   "MACAddress" : "ff-ff-ff-ff-ff-ff",
   "ParentImageFileName" : "\\Device\\HarddiskVolume1\\Windows\\SysWOW64\\mshta.exe",
   "DetectName" : "Malicious Document",
   "LocalIP" : "10.1.1.1",
   "SHA1String" : "0000000000000000000000000000000000000000",
   "ProcessStartTime" : 1587556118,
   "SHA256String" : "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
   "CommandLine" : "\"C:\\WINDOWS\\system32\\cmd.exe\" /c COPY \"\\\\some_host.some_domain.com\\Shares\\Database.lnk\" \"C:\\Users\\john\\Desktop\\Database.lnk\"",
   "DetectDescription" : "Mshta launched under Microsoft Word with an unusual command line. This might result from a malicious macro in a lure document. Investigate the process tree to find the originating file and look for similar files delivered to other hosts.",
   "PatternDispositionValue" : 2048,
   "FileName" : "cmd.exe",
   "IOCValue" : "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
   "FilePath" : "\\Device\\HarddiskVolume1\\Windows\\SysWOW64",
   "SeverityName" : "High",
   "Objective" : "Gain Access",
   "MD5String" : "ffffffffffffffffffffffffffffffff",
   "DetectId" : "ldt:e1c477d9efe7430f6851179600d398d7:133145662771",
   "GrandparentImageFileName" : "\\Device\\HarddiskVolume1\\PROGRA~2\\MICROS~1\\Office14\\WINWORD.EXE",
   "Technique" : "Spearphishing Attachment",
   "FalconHostLink" : "https://falcon.crowdstrike.com/activity/detections/detail/e1c477d9efe7430f6851179600d398d7/133145662771?_cid=1e20fa2271ea440190fcd7c4f78e4556",
   "ParentProcessId" : 773330802026,
   "MachineDomain" : "some_domain",
   "SensorId" : "e1c477d9efe7430f6851179600d398d7",
   "PatternDispositionFlags" : {
      "OperationBlocked" : False,
      "KillParent" : False,
      "Indicator" : False,
      "Detect" : False,
      "PolicyDisabled" : False,
      "KillProcess" : False,
      "QuarantineMachine" : False,
      "KillSubProcess" : False,
      "SensorOnly" : False,
      "ProcessBlocked" : True,
      "QuarantineFile" : False,
      "Rooting" : False,
      "InddetMask" : False
   },
   "IOCType" : "hash_sha256",
   "ParentCommandLine" : "\"C:\\Windows\\SysWOW64\\mshta.exe\" \"\\\\some_host.some_domain.com\\Shares\\Database.hta\" ",
   "UserName" : "e020501",
   "ProcessEndTime" : 1587556118,
   "Tactic" : "Initial Access",
   "ProcessId" : 773334187356,
   "Severity" : 4,
   "GrandparentCommandLine" : "\"C:\\Program Files (x86)\\Microsoft Office\\Office14\\WINWORD.EXE\" /vu \"C:\\Users\\john\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.Outlook\\561LSPB5\\Database.docx\""
}

class TestCase(ACEBasicTestCase):
    def setUp(self):
        super().setUp()
        if not integration_enabled('falcon'):
            raise unittest.SkipTest("falcon integration not enabled")

    def test_process_detection_event(self):
        collector = FalconCollector()
        submission = collector.process_detection_event(metadata, event)
        self.assertTrue(isinstance(submission, Submission))

        self.assertEquals(submission.details, event)
        self.assertEquals(submission.observables, [
            {'type': 'hostname', 'value': 'HOSTNAME'},
            {'type': 'user', 'value': 'e020501'},
            {'type': 'file_name', 'value': 'cmd.exe'},
            {'type': 'file_path',
             'value': '\\Device\\HarddiskVolume1\\Windows\\SysWOW64'},
            {'type': 'md5', 'value': 'ffffffffffffffffffffffffffffffff'},
            {'type': 'sha1', 'value': '0000000000000000000000000000000000000000'},
            {'type': 'sha256',
             'value': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'},
            {'type': 'ipv4', 'value': '10.1.1.1'},
            {'type': 'file_path',
             'value': '\\Device\\HarddiskVolume1\\Windows\\SysWOW64\\mshta.exe'},
            {'type': 'file_path',
             'value': '\\Device\\HarddiskVolume1\\PROGRA~2\\MICROS~1\\Office14\\WINWORD.EXE'},
            {'type': 'command_line',
             'value': '"C:\\WINDOWS\\system32\\cmd.exe" /c COPY '
                     '"\\\\some_host.some_domain.com\\Shares\\Database.lnk" '
                      '"C:\\Users\\john\\Desktop\\Database.lnk"'},
            {'type': 'command_line',
             'value': '"C:\\Program Files (x86)\\Microsoft '
                      'Office\\Office14\\WINWORD.EXE" /vu '
                      '"C:\\Users\\john\\AppData\\Local\\Microsoft\\Windows\\Temporary '
                      'Internet Files\\Content.Outlook\\561LSPB5\\Database.docx"'},
            {'type': 'command_line',
             'value': '"C:\\Windows\\SysWOW64\\mshta.exe" '
                      '"\\\\some_host.some_domain.com\\Shares\\Database.hta" '},
            {'type': 'file_path', 'value': 'C:\\WINDOWS\\system32\\cmd.exe'},
            {'type': 'file_location',
             'value': 'HOSTNAME@C:\\WINDOWS\\system32\\cmd.exe'},
            {'type': 'file_path',
             'value': '\\\\some_host.some_domain.com\\Shares\\Database.lnk'},
            {'type': 'file_location',
             'value': 'HOSTNAME@\\\\some_host.some_domain.com\\Shares\\Database.lnk'},
            {'type': 'file_path', 'value': 'C:\\Users\\john\\Desktop\\Database.lnk'},
            {'type': 'file_location',
             'value': 'HOSTNAME@C:\\Users\\john\\Desktop\\Database.lnk'},
            {'type': 'file_path',
             'value': 'C:\\Program Files (x86)\\Microsoft '
                      'Office\\Office14\\WINWORD.EXE'},
            {'type': 'file_location',
             'value': 'HOSTNAME@C:\\Program Files (x86)\\Microsoft '
                      'Office\\Office14\\WINWORD.EXE'},
            {'type': 'file_path',
             'value': 'C:\\Users\\john\\AppData\\Local\\Microsoft\\Windows\\Temporary '
                      'Internet Files\\Content.Outlook\\561LSPB5\\Database.docx'},
            {'type': 'file_location',
             'value': 'HOSTNAME@C:\\Users\\john\\AppData\\Local\\Microsoft\\Windows\\Temporary '
                      'Internet Files\\Content.Outlook\\561LSPB5\\Database.docx'},
            {'type': 'file_path', 'value': 'C:\\Windows\\SysWOW64\\mshta.exe'},
            {'type': 'file_location',
             'value': 'HOSTNAME@C:\\Windows\\SysWOW64\\mshta.exe'},
            {'type': 'file_path',
             'value': '\\\\some_host.some_domain.com\\Shares\\Database.hta'},
            {'type': 'file_location',
             'value': 'HOSTNAME@\\\\some_host.some_domain.com\\Shares\\Database.hta'}])

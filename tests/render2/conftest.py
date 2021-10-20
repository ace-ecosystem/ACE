from datetime import datetime, timedelta
import os
import tempfile
import time
import pathlib
import uuid

import docker
import pytest
import redis
import dotenv

#--------------------------------------------------------------
# Common variables
#--------------------------------------------------------------

JOB_QUEUE_KEY = 'render:queue:incoming'
JOB_ID = str(uuid.uuid4())
JOB_DETAILS_KEY = f'render:job:{JOB_ID}'
JOB_DETAILS_BASE = {
    'id': JOB_ID,
    'output_type': 'redis',
    'output_name': 'pic.png',
    'width': '1280',
    'height': '1024',
    'status': 'queued',
}
JOB_DETAILS_HTML = {
    'content_type': 'html',
    'content': '<html lang="en">\n<head>\n  <meta charset="utf-8">\n\n  <title>My_test_page</title>\n  '
               '<meta name="description" content="test page">\n  <meta name="author" content="KylePiper">\n\n'
               '</head>\n\n<body>\n    <p>My test content</p>\n</body>\n</html>',
    **JOB_DETAILS_BASE,
}
JOB_DETAILS_URL = {
    'content_type': 'url',
    'content': 'https://google.com',
    **JOB_DETAILS_BASE,
}
NGINX_TEST_KEY = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUpRZ0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQ1N3d2dna29BZ0VBQW" \
                 "9JQ0FRRGdxR1NJa1A1UzdXeG8KbmkrOFVUNUFQZ2IxWFF1NFdvdmhpNXhFRElncnJja0F4VmtwSHlKbTQvdFQ5MTJoSHhrTGt0" \
                 "YUZsckpqeDJsYgpPZUlid0VnMXJDclZ2c0h5WUtvQUxzczNPSHJwWGFCMXpTaXV6dVd6Z2k1U1l1NUZiY2R6OGhmeXFqeG5VbF" \
                 "ZmCkVYZXRLaVVybk5uZHJkbllmU2ZVYWJVbktZbVBFYWFmbFpqeDFkSDhkUXYzWDVHTTJNejB2RmFHOWxXVFhaRUwKNWxyYVds" \
                 "dE1TWVRpcDlDaElvdzVibkgrMGNnRzdUbkRKeWlkY3l2c1MzM0VMQzBWK2xaOTRDZFZJWmFJd0RTRwpnTUo3Y3pCeVU0T3ZIeF" \
                 "RvTjlqOTVsODJSLzVQaENJZWgyMXYyaHYvOVRaclFnSFQ3Zks4emg0QS9BbUovTTZXCldUMStFSFZWZ2pyZXppWTRaRlEvUmtF" \
                 "aUNhV0lYWDlGU2xRRnpNS0Nld3BXUFVYYkI3MWUyOUtsdzJ3RVQ3UmEKenJtZjNidDYxNjVoWE9VL1ZuanBHYnV2d205Um83K3" \
                 "hvRnlUV3IvdGlxZ3V3T0JnbHliVk5ka1IxWW92aExObQpDRHI3M0lLbUt4dGxUK09GVEtLU1lJdzNTazN6VUpXOXcydXBwRUtt" \
                 "MVJERTlmbSt5eml5UTd4eE82QjVGenJ0CnMzSG00T3dqc3JxczIyYzBBNmVadHpTQWJCRlA4U1RvVnEwaU9mUFdUV1RueVFKZm" \
                 "xZaUxzdGg2Tlhsam01VWQKblpQK0ZKS01RZ3c4RE1RTTRpNWhRWEJBZ3JhRTJ5TTJGYVcvMmNiSkJrYmY5M09BdmVmc1pXU1U5" \
                 "T1dxR3F5VgozcHQzazAvNGRLcVFuZDg0eG11NGsvVTNwYmtzS1FJREFRQUJBb0lDQUNGa1JoVWFZQUxaY1V5WGZvYmlHSHVaCi" \
                 "9KVEpzSzFGSUJkMUZkUHpmT1hwSGNBMGxRME1xS05jYllYTWRhazJJeFhhVEhKc3RMVXA5Wm51bjVINllZRkEKeHRrZ1VsbUJU" \
                 "cU5hVVRBeS8rbmgxYkRNdnFoRTdsVmhHeHQ1d3VxazU0bHZTV256TGFrNXpxQ2p5d0w5Q2F0UwowL3NrRlFZZGpDY0JVMEN2NX" \
                 "RkU0MwOGJBREdwMDExUDFHaC9WdlgxWDNsYzZRdUVYN0hZclc5MFhMcXB4WG93ClQwVVZKbWhjNXpTK0dzbUNTdFhrdXJvci90" \
                 "aHdQdTRQUm5FN0U3UjVraE9CbHJjTG1BRlplRFVwdkQ1M0g1Tk8Kb0hzT0JxQ0JkSXBBakpSWDNRL2FsdXVzdTNKdG04M09sN2" \
                 "tYaFlnSGpSWE5HUjZTVjZTZjQrRHJBTDNWR210RQo3L29ZdEVTbzM0ZGt2OE9kM0lwd1dZbE9zUUlONkVpSUx3bmdaaHBZMG9t" \
                 "Zk5nM1ZBUS9uOHRzMFcrVjd3bUFKClRYU0R2N081ZjBOM093V0hJaFdUb2IycGg5dS9tMzlDQ1ZCSjdNNVcrNlVNbFhMK1ZYUW" \
                 "VqKzc3Z01qSHAxY0wKZi8rdmsxd2dYNS80bklsaTJzNHlIL2JvdzYzR1BvNUVFSmEyTVp3MXNUQi85TmFUbUlzTHRNbnNBdW5q" \
                 "b1JzTQprRVkyQnllMXlzaWZsaHJjUExyN3RFVGhUMytIS25RdVRWR2V1YzdtZVh6WkdsRVhNRmlvQjhMU2hHYlpKdzhTCldtcj" \
                 "RUc29xVThUQ2taQ3hUckZoOTBLMzR1OUJYQjVBTDZEMGswU09GTlkrdmljZVVxQ0NJd0pmS2tIS3N5OVcKTzcwcnZsL0h3dXk2" \
                 "cXU2UlhtUEZBb0lCQVFEMlhmcVk5SWdiZEFEVXB2VENhVTRqZnExRDQzY1AyTjAwbmdIWAp5bW50N08xMHRXTGVKVitUZ1FHVl" \
                 "RjZnhoT3JDdzhVV25WanMvMVpoNGhVUTBFYWl5RjlXR2FodEhUMGRwZVFTCkEzWnZkZXBLTUk0UUFRbDlBTGg1T1lyTUUyWUhO" \
                 "dXcrQUdMZDRSendTV3FwUjNtV2JoN2ZqalFhbkx5T0hFWWwKeXVwQ0RQQjRLdGN6YmY5QW13S2NZRlFlOHRhVVdCclBYVjc3dC" \
                 "9iN0RhUkwyMHVWUmNRQllpRWFRNCtLSEtPNQowbWtFTXI2dmErSmNoUXhaYVV0MkFBVFZ2ajBybXpGOXJ2cUtkS3JLbE1SemJS" \
                 "SGVnUUI5OTBRTlpsdmFKZzdjCm95aVZSOUVIZzZJSHRpS1lFdDNMWkZOVzVWcWNNQXhySUlrSmJFK1kwRmRxb01BSEFvSUJBUU" \
                 "RwY1IwUHJwZFEKZDFNUkdISWt1WC9maTM4R3VIRWZNWW00ZmhnRXFpenVSU3VIY3JMWmlBR0JjWGpWbEE2WWRkb2ZjU3dhY0dM" \
                 "WQpndE1yOGZrSmtRc0M0RkZ4SktLUXVoVWVpODlYYzNHQmk0dXpIWTI4MmZNZnZrNVZFQmxOTVR4d1YzK2YvRkczCjlES1p2cW" \
                 "tDSjFNemwvRi9VM2l4Z2RnN2VXY1BxeWRKSkFhRDZ6UnJaMDg3R1p1TE5RNEdxL0I4N3pSTHdtaCsKUTlQNXA5d2tvd3k3SWVm" \
                 "ZlZkelFEd0pWbVpTT1M3TDNaaXBMVXVLMU00WU44TVdwK2hCOVA1U3JCUVRxY0xNdApZNWExV0NDQVQxZ2NWbVhkd1VWQ0dyQV" \
                 "RNT1daS2xvc1Voam9TZDF4Vk9Ec1Z4eEhWdmYwUnRKRHVsNG9UQkFOCnFTdVpvQm1LaEVaUEFvSUJBRXN1TEkzR2VVNWZYTzJI" \
                 "c1VNdVhXRHBoRGdtVHF2d1VyaCt5ek10bXB1M1pGTHMKRXlxVkh4QmxHcldVRWNLNisrVEpWdmhxdGJ0RXcvaUV4RWJvTjlYdT" \
                 "dXRFozWkxHakdMaXY3RmJpeVhDUnVleQozM2MweWM5eWk5aTZYWWVmRjlCMXl5dTBkSGNlL2ZTNWdxbjduTGZ5RE12Tm1rclFy" \
                 "NTF5TlZuTkRTVnd5MlR3Ck5kR0U3SktyZXVWN1k5QTU3STlDUDVRdCt4RTNkMC92UHNiRE9kSm9nc0tsVGxLMGNUWUZQVlUwUj" \
                 "BXM3NvYlgKbGpFRGpOd3dESTRLdlc3NGFiUkgzSmRzOFJtVk5wVXhScTJ1aC9odFIxZ3BQNFFUUzA1THROZFJsczNQSjVOeQpj" \
                 "TnlIa1JEMUdPZTdTczlHbUJyM2NxS3lQLzgzSlNjTjFNOCtGTHNDZ2dFQkFOYjJWem1DbjBuMHAyUmRxM1pQCjd3V3VFZW5oWE" \
                 "NIS1h6U3B3SHBETHA2MnlVK3YraXZBUndxb3NBbVVqaUFzbmhCSUNjSEs3ZXJNQmFNNDdnZTIKTFhxWGo4ZHRZZGw5MFViUW5i" \
                 "eTh6Sy9yRFZpQ0JXdjdFeHVQQmRqa3V6Zk8rQVhIUFBuWXduTnZoa3ozT2ZDRwp2K0lKcjlOOHpPNUFVQnJzUDFBNVhqTEczcz" \
                 "BKZ0xyS1pqWlk3VmV5SWxsWWFWclNkc2l3bThKeHVUZnpNQS80CnFSZUZNRjBEVnhPc1RveitvTUtyeUlCeTdzMXY1TjNSTlVl" \
                 "UENLWHVaTkxCQXFpOU5YcWhEdzNqMy9yYnpRbjYKaG51SnY4SUZZRDV3RHVXTktFL3pwUmVjL2R5aGNDNFZhQTJhWmFyMzFkcD" \
                 "JnTmJuUGg5RGM2RHd2L3AyYUM2YQpnWmNDZ2dFQUlLVkVvcExsRUQ4Z2RpdUNHK0Njb0tLS2YreW5HNlZXTWN0MEJ1elArNEQw" \
                 "OW5iOTJKSExPbHJ0CkhNemRwSm9pR1lFUkEwSkVuekR3OUlMKzN1RGdjMVVhWjA0aEozSUxVYzl4TXRSek12TnFVR2dhd0d1Mk" \
                 "JaQWMKUVBCSmxZanRGckFlRllGRUwrZVQwUy9MTTk2OXlzODZ3dkk0b0wzblhXeE0ydm5qTi9VNUphYlJxYUtSSEhHMQpUR0RV" \
                 "aWdIMjJ2TkRrZUJmYlNReE5lSTJZTUdqeUk3NnJ1WDJ5ZzRSZEx2aHhsRVliZXRBSE5wTURoTDlHZXh4CjZtWE1IRGVpSHcwYk" \
                 "J4eDVBdEFxR2l4elhHTzhKL2dxL3lYdll4b1YzY0hObjYwRjBJZ2RzNGgrZWg0QzNOWDgKbS96RnNZTWxPYUZRT0FVaFB0RXgy" \
                 "TjZtWTVidWJ3PT0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="
NGINX_TEST_CERT = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZURENDQXpRQ0NRQ1NYN1loNjR2QnZqQU5CZ2txaGtpRzl3MEJBUXNGQ" \
                  "URCb01Rc3dDUVlEVlFRR0V3SlYKVXpFTk1Bc0dBMVVFQ0F3RVQyaHBiekVUTUJFR0ExVUVCd3dLUTJsdVkybHVibUYwYVRFVk" \
                  "1CTUdBMVVFQ2d3TQpWR2h5WldGMElFbHVkR1ZzTVI0d0hBWURWUVFMREJWRmVIUmxjbTVoYkNCVWFISmxZWFFnVTNGMVlXUXd" \
                  "IaGNOCk1qQXdOekUzTWpBek9EUTNXaGNOTWpFd056RTNNakF6T0RRM1dqQm9NUXN3Q1FZRFZRUUdFd0pWVXpFTk1Bc0cKQTFV" \
                  "RUNBd0VUMmhwYnpFVE1CRUdBMVVFQnd3S1EybHVZMmx1Ym1GMGFURVZNQk1HQTFVRUNnd01WR2h5WldGMApJRWx1ZEdWc01SN" \
                  "HdIQVlEVlFRTERCVkZlSFJsY201aGJDQlVhSEpsWVhRZ1UzRjFZV1F3Z2dJaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUNEd0" \
                  "F3Z2dJS0FvSUNBUURncUdTSWtQNVM3V3hvbmkrOFVUNUFQZ2IxWFF1NFdvdmgKaTV4RURJZ3JyY2tBeFZrcEh5Sm00L3RUOTE" \
                  "yaEh4a0xrdGFGbHJKangybGJPZUlid0VnMXJDclZ2c0h5WUtvQQpMc3MzT0hycFhhQjF6U2l1enVXemdpNVNZdTVGYmNkejho" \
                  "ZnlxanhuVWxWZkVYZXRLaVVybk5uZHJkbllmU2ZVCmFiVW5LWW1QRWFhZmxaangxZEg4ZFF2M1g1R00yTXowdkZhRzlsV1RYW" \
                  "kVMNWxyYVdsdE1TWVRpcDlDaElvdzUKYm5IKzBjZ0c3VG5ESnlpZGN5dnNTMzNFTEMwVitsWjk0Q2RWSVphSXdEU0dnTUo3Y3" \
                  "pCeVU0T3ZIeFRvTjlqOQo1bDgyUi81UGhDSWVoMjF2Mmh2LzlUWnJRZ0hUN2ZLOHpoNEEvQW1KL002V1dUMStFSFZWZ2pyZXp" \
                  "pWTRaRlEvClJrRWlDYVdJWFg5RlNsUUZ6TUtDZXdwV1BVWGJCNzFlMjlLbHcyd0VUN1JhenJtZjNidDYxNjVoWE9VL1ZuanAK" \
                  "R2J1dndtOVJvNyt4b0Z5VFdyL3RpcWd1d09CZ2x5YlZOZGtSMVlvdmhMTm1DRHI3M0lLbUt4dGxUK09GVEtLUwpZSXczU2sze" \
                  "lVKVzl3MnVwcEVLbTFSREU5Zm0reXppeVE3eHhPNkI1RnpydHMzSG00T3dqc3JxczIyYzBBNmVaCnR6U0FiQkZQOFNUb1ZxMG" \
                  "lPZlBXVFdUbnlRSmZsWWlMc3RoNk5YbGptNVVkblpQK0ZKS01RZ3c4RE1RTTRpNWgKUVhCQWdyYUUyeU0yRmFXLzJjYkpCa2J" \
                  "mOTNPQXZlZnNaV1NVOU9XcUdxeVYzcHQzazAvNGRLcVFuZDg0eG11NAprL1UzcGJrc0tRSURBUUFCTUEwR0NTcUdTSWIzRFFF" \
                  "QkN3VUFBNElDQVFBZU9oblRrUkpQYkFSR2hVNEZZckRYCkYyZnNLRkVPR1JON1lCWDZML2Mwald0L1V6eTNrc3ZNbHhjR3h4c" \
                  "1pRY2RFQVc2SVZDQWFXZHd2bUtvbzhLNzAKZVRNdkNodmg3ZVpqZGRoQ3pOKy9zVGJmK0g0VEdjYzFaTXFPcnJZdzlzajRpem" \
                  "EvdmlFbEV3SzdGT200Ymt5awpnYzllL2xoTEpZbUgrSURhenQ2VUtjdnN6U2dOMzRVMkx3akNpcGZvQ1VUVER2UGJkQlVCNmU" \
                  "wU1hMQnRaYTJXClhwd0syRTQ5VFB4a1V6Z0Y1N1VjOGFGZWFZdFVZTmhaNW9LL0h4T1FQamg2WVlUT2k0UmdVd3BPOHpYMWIr" \
                  "eEEKVVFjVlpGU3RJYVNtZGplNXpCaFJ2RGdkK25OV2dhcDF5MFBNeWlONU9ENnlOb1A1SHhKbzlUdjZrODhuckQvNgpLbHJwY" \
                  "0d6VzBxalJ5bDZiSTloazZhQXhXclNNNzdjNUN2VFdYNjhQckVoMVJEU0psOTRPaWZJS1Z5UUxlc3RpCkRLTEo0SkNWd2V3OH" \
                  "B0eHk0V0l0a3pVUnBpOU1uaThxSVZ5YkVwZnVnazVqdkpNRGE5Uk1hZ2QzZ2hXWmdUaC8KUElRT01HL3ovTjNWTmhlRTM2OW1" \
                  "3YWxCaFFUZjJHUG4yTkl2LzZldkMrenBvZnZhQ1dRdnJMcjE2c1U4bDUyaQo0UEo2TjdyS3M4YStIekpXT1pNOHVpdXdZWFRI" \
                  "NWNnOTVrLzRMOGFoTERaWW9WVHk4N09VUFQ4ZHJTd0tGaFVWCjFWbXAwcGtSNW83Q1FDdjg0R1kyQXYxbVZIM1Y0SzNOeG5NZ" \
                  "1VlME1RRHRRTEwxTGhiN2lGMFpiT28reG1Id0kKZWl3RjlYUmFQdVRac3dHT0Y5TjdUQT09Ci0tLS0tRU5EIENFUlRJRklDQV" \
                  "RFLS0tLS0K"
NGINX_TEST_CA = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZVakNDQXpvQ0NRRGl5RGd4aWZsS3B6QU5CZ2txaGtpRzl3MEJBUXNGQUR" \
                "Cck1Rc3dDUVlEVlFRR0V3SlYKVXpFTk1Bc0dBMVVFQ0F3RVQyaHBiekVUTUJFR0ExVUVCd3dLUTJsdVkybHVibUYwYVRFVk1CTU" \
                "dBMVVFQ2d3TQpWR2h5WldGMElFbHVkR1ZzTVNFd0h3WURWUVFMREJoRmVIUmxjbTVoYkNCVWFISmxZWFFnVTNGMVlXUWdRMEV3C" \
                "khoY05NakF3TnpFM01qQXpPRFE1V2hjTk1qRXdOekUzTWpBek9EUTVXakJyTVFzd0NRWURWUVFHRXdKVlV6RU4KTUFzR0ExVUVD" \
                "QXdFVDJocGJ6RVRNQkVHQTFVRUJ3d0tRMmx1WTJsdWJtRjBhVEVWTUJNR0ExVUVDZ3dNVkdoeQpaV0YwSUVsdWRHVnNNU0V3SHd" \
                "ZRFZRUUxEQmhGZUhSbGNtNWhiQ0JVYUhKbFlYUWdVM0YxWVdRZ1EwRXdnZ0lpCk1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QX" \
                "dnZ0lLQW9JQ0FRQ2JTSDdSdHE3MlFxYUtzWUtTVzdXbW82OU8KVmZoK0lhT1VGWksvRjVHZTRDcWdaSXlSVlZVZ2hETVZudVJDW" \
                "VFwcWRtODJNKzhnSzk3amxFUVVNbzYzTGk2cwo2N04ra2drczNINnVWQlJocEZpZ3RRbm9FN1Vad05nR2F5eDVva3k0UEVyRUFj" \
                "ZjBDNXBNTTlQT3c2cWtqRkNVClpVNFJaY21QOHF4NWJsVmU5SFFZcFVlZ3hZSVl3Vk5tZWF2RFFRS1VHQUtwdVljTWN6c09zU2Y" \
                "5aW1HQmZoOFoKamRwYW5VVHJSeXpSbnZGQnZaMGFjbmh6YzVtcVNhRHduVTlBblovWWNqcXVQUzVLRnlDQjJXVXV3RFU2eHNkMg" \
                "p3MjFidG03WVlOL0ZraU5wR1FIelpTUEJoYU9Sd2IwYnBmSTJsejlZMER5VWh6M2hZRUQ5NFN0SmcwQU1GbVlECnBvM2xhVVJWQ" \
                "kdQYkdnZGs0RE1hNzBLYU5QSURZaTRWNUFVN2JBdVRIUTlVNVB3blhibEFxVE9pdUYrZk8va0wKUHJ2cURxdE9OR2t4L2VRY1Bh" \
                "bTZWb1JhSkVFYWhGQ2xWMGRzZGRiWmdzOVloV0l3NHhCS1JXUkQ1UTM2b2JQZgpjaTJqRDUxSDQ2cEFiTGlZWG5sMHdEVmw0Vm5" \
                "wY3FTWVR2RjNYMkpVS1owKzVHSEV6VXdPc204dlkrWmpRbHFtCmdaOC9DV2pKL1JOY05WemlwUjhOcmpEZGMrY1hPWnhBUnRBOF" \
                "JFWlp2MnE5QzFWWGc2TmUrTnY1ZHEyclVlSE0KRUpCWW9oN1RUZTh2a3NnNDZqaGxOR2NZRVpMRG1RcDBYVjN1NjBHbnFwQThEb" \
                "WFJWWlNZSs4R3V4dHRFTU91QgpNcFJYci83M1JDMXd5aTBRaHdJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUJsb3A5" \
                "UnpzeWl0YVBSCkpPWVQraHpBK0ZXb1M2eWZoRmozZ2RkSm5vc1lvNTBrRi9kUnp4aHJ1VXhRUmEzZlpoOXFMcG1UV0NaY2hnaWs" \
                "KSWJicGFqdVgybkM3bDg5R3duajBDUHNEakxGbUJ2N21rNzRkWEMyeTdlL0IwVFFHOGpuRkhTd2NhLzFkb3JlaQpQT2llNVUzd0" \
                "VYd3d6OVBIemJaOTdoNGlwdGtjc3ptOTQrOWx1RFVHTVd0V29MK2k1Zkk0aGZvWmNaa2tWQ1dBCmRMd0pZV1JOK1phVFNCMzN4Z" \
                "UthcjliUFRSUGNtUWI0QnljMGU5UWRDb3dFelk1N2d0RHd0ZWNDWllkUjIwanoKcDdMMG1iRGptZHF4b1JKQ1grUkk1WXo1ZmRM" \
                "MjY1Nmt5R2NEa2ZqUkhVWWFpbHB2NXNWakJVZHZ2K1ZvRGh5SwpKL05heUdxbENiNW1oWVZqc3ZpVGlDOFdzWWZOcHdxYkxESGg" \
                "vcXlMWS9TTUkxWFdHcDV1Tm5UemxaeVE1NkQrCmZ3SHhQTHc2NEJkdURMV3p1dktJbm5VaXlVQzQ0bmNGMUlUUHU4UFZuczF3K3" \
                "ppR0VpeG5xNzl6MlY4RUtIVDYKdWxrOVlpbFpVc29PZzVVM1pqSTZZUy9OWkU1YXI3TkFjTFRaOXVzVlpqRGdwL1lKTmFEVHdxc" \
                "UxSVmdOUlZ5dAp0RDRlMlpWT01ZY1lkNitkaHJjayt2Y0w1Y2dSODRCODgzY1l4b1lNOXVXS2FjblNsd2s4R0JMY0cxNGhtOUJY" \
                "CkhiM0F0SW94MFhIeXNJa2pOdDB1eG9wOFNoUUZpZlZOOSt2ZlhNWi9SODVKWHdiS090cHRBK0hPdVpXdTYxWEsKMHgyeHQ4cFd" \
                "zYWtJSE1kVDFHSmlRaDI0cjFPeHV3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="


@pytest.fixture(scope='function')
def redis_client(redis_server):
    """A basic, empty redis client with encoding configured."""
    r = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True, encoding='utf-8')
    r.flushall()
    yield r


def remove_existing_container(docker_client, container_name) -> None:
    """Helper class to remove existing running container if it was left
    behind from other tests."""
    containers = docker_client.containers.list(all=True)  # even stopped containers
    container_names = {container.name: container for container in containers}

    if container_name not in container_names:
        return

    _container = container_names[container_name]
    if _container.status == 'running':
        _container.stop()
    _container.reload()
    _container.remove()


@pytest.fixture(scope='module')
def vars():
    """Constants to be used by tests and fixtures"""
    class Vars:
        REDIS = 'redis:latest'
        RENDER = 'render'
        CONTROLLER = 'controller'
        SELENIUM = 'selenium/standalone-chrome:latest'
        FASTAPI = 'tiangolo/uvicorn-gunicorn-fastapi:latest'
        NGINX = 'nginx:alpine'
        NETWORK = 'pytest_render'
        REDIS_DNS_NAME = 'test.render.redis'
        RENDER_DNS_NAME = 'test.render.renderer'
        CONTROLLER_DNS_NAME = 'test.render.controller'
        NGINX_CUSTOM = 'render_nginx'
        NGINX_DNS_NAME = 'test.nginx.renderer'
    yield Vars


@pytest.fixture(scope='module')
def network(vars):
    """Docker network to use

    User-defined network allows referencing other containers by
    name."""
    _network = None
    try:
        d = docker.from_env()
        # If network didn't get cleaned up during the last run, then don't recreate it.
        existing_networks = {network.name: network for network in d.networks.list()}
        if vars.NETWORK not in existing_networks:
            _network = d.networks.create(vars.NETWORK, driver="bridge")
        else:
            _network = existing_networks[vars.NETWORK]
        yield _network
    finally:
        _network.remove()


@pytest.fixture(scope='function')
def redis_server(vars, network):
    """Redis server running in Docker."""
    container = None
    try:
        d = docker.from_env()
        images = d.images.list()
        redis_found = False
        for image in images:
            if vars.REDIS in image.tags:
                redis_found = True
                break
        if not redis_found:
            d.images.pull(vars.REDIS)

        # Remove running or stopped containers that might be left behind from previously
        # failed tests. The container names will conflict with the new containers being
        # created.
        remove_existing_container(d, vars.REDIS_DNS_NAME)

        container = d.containers.run(
            vars.REDIS, detach=True, network=network.name,
            ports={'6379/tcp': ('127.0.0.1', 6379)},
            name=vars.REDIS_DNS_NAME,
        )
        # Give it some time to start before throwing it to the wolf pack.
        time.sleep(5)
        yield container
    finally:
        container.stop()
        container.stop()
        container.remove()


@pytest.fixture(scope='function')
def renderer_container(vars, network, printer):
    """Run the renderer container"""
    container = None
    image = None
    random_tag = datetime.now().strftime('%s')
    render_tag = f'{vars.RENDER}:{random_tag}'
    d = docker.from_env()
    try:
        images = d.images.list()
        selenium_found = False
        # See if selenium image is already local
        for image in images:
            if vars.SELENIUM in image.tags:
                selenium_found = True
                break
        if not selenium_found:
            d.images.pull(vars.SELENIUM, )
        # Build renderer container


        # build up the path to the context and the path to the Dockerfile
        relative_context_path = pathlib.Path('render2/src/shared/')
        relative_docker_path = pathlib.Path('render2/src/renderer/Dockerfile')
        current_dir = pathlib.Path(os.getcwd())
        context_path = str(current_dir.joinpath(relative_context_path))
        docker_path = str(current_dir.joinpath(relative_docker_path))
        # context_path = get_abs_path_relative_to_ace(relative_context_path)
        # docker_path = get_abs_path_relative_to_ace(relative_docker_path)

        # This blocks until the container is built
        _ = d.images.build(path=context_path, dockerfile=docker_path, tag=render_tag, use_config_proxy=True)

        # Remove running or stopped containers that might be left behind from previously
        # failed tests. The container names will conflict with the new containers being
        # created.
        remove_existing_container(d, vars.RENDER_DNS_NAME)

        # Proxy info to load into renderer container if applicable
        dotenv.load_dotenv()

        local_proxy_host = os.environ.get("LOCAL_PROXY_HOST")
        local_proxy_port = os.environ.get("LOCAL_PROXY_PORT")
        local_proxy_user = os.environ.get("LOCAL_PROXY_USER")
        local_proxy_pass = os.environ.get("LOCAL_PROXY_PASS")

        environment = {
            'REDIS_HOST': 'test.render.redis',
            'REDIS_PORT': 6379,
            'REDIS_DB': 0,
            'JOB_QUEUE_KEY': 'render:queue:incoming',
            'SLEEP': 2,
        }

        if local_proxy_host is not None:
            environment['PROXY_HOST'] = local_proxy_host
            environment['PROXY_PORT'] = local_proxy_port

        if local_proxy_user is not None:
            environment['PROXY_USER'] = local_proxy_user
            environment['PROXY_PASS'] = local_proxy_pass

        container = d.containers.run(
            render_tag,
            detach=True,
            network=network.name,
            environment=environment,
            name=vars.RENDER_DNS_NAME
        )
        time.sleep(10) # Make sure the container has time to start up
        yield container
    finally:
        # If the container doesn't exist, the image might, so
        # go ahead and try to remove image even if the container
        # doesn't exist.
        try:
            container.reload()
            printer(f'Container status: {container.status}')
            printer(container.logs().decode('utf-8'))
            if container.status == 'running':
                container.stop()
            container.remove()
        except Exception:
            pass

        try:
            d.images.remove(render_tag)
        except Exception:
            pass


@pytest.fixture(scope='function')
def controller_container(vars, network, printer):
    """Run the renderer container"""
    container = None
    image = None
    random_tag = datetime.now().strftime('%s')
    controller_tag = f'{vars.CONTROLLER}:{random_tag}'
    d = docker.from_env()
    try:
        images = d.images.list()
        fastapi_found = False
        for image in images:
            if vars.FASTAPI in image.tags:
                fastapi_found = True
                break
        if not fastapi_found:
            d.images.pull(vars.FASTAPI, )

        # build up the path to the context and the path to the Dockerfile
        relative_context_path = pathlib.Path('render2/src/shared/')
        relative_docker_path = pathlib.Path('render2/src/controller/Dockerfile')
        current_dir = pathlib.Path(os.getcwd())
        context_path = str(current_dir.joinpath(relative_context_path))
        docker_path = str(current_dir.joinpath(relative_docker_path))

        # This blocks until the container is built
        _ = d.images.build(path=context_path, dockerfile=docker_path, tag=controller_tag, use_config_proxy=True)

        # Remove running or stopped containers that might be left behind from previously
        # failed tests. The container names will conflict with the new containers being
        # created.
        remove_existing_container(d, vars.CONTROLLER_DNS_NAME)

        container = d.containers.run(
            controller_tag,
            detach=True,
            network=network.name,
            environment={
                'REDIS_HOST': 'test.render.redis',
                'REDIS_PORT': 6379,
                'REDIS_DB': 0,
                'JOB_QUEUE_KEY': 'render:queue:incoming',
                'SLEEP': 2,
                'PORT': 8080
            },
            name=vars.CONTROLLER_DNS_NAME,
            ports={8080: 8080}
        )
        time.sleep(10) # Make sure the container has time to start up
        yield container
    finally:
        # If the container doesn't exist, the image might, so
        # go ahead and try to remove image even if the container
        # doesn't exist.
        try:
            container.reload()
            printer(f'Container status: {container.status}')
            printer(container.logs().decode('utf-8'))
            if container.status == 'running':
                container.stop()
            container.remove()
        except Exception:
            pass

        try:
            d.images.remove(controller_tag)
        except Exception:
            pass


@pytest.fixture(scope='module')
def temp_volume():
    """Temp directory to mount to Docker containers."""
    with tempfile.TemporaryDirectory() as directory:
        yield directory

def get_abs_path_relative_to_ace(relative_path_string: str):
    current_path = os.getcwd()
    current_path_parts = current_path.split(os.sep)
    if current_path_parts:
        while current_path_parts[-1] != 'ace':
            current_path_parts.pop()
    ace_path_parts = current_path_parts
    abs_path_parts = [*ace_path_parts, *relative_path_string.split(os.sep)]
    abs_path = os.sep.join(abs_path_parts)
    return abs_path


class MockJobQueue:
    """A mock JobQueue that does not require redis, to allow for unit tests"""

    def __init__(self, *args, **kwargs):
        self.backing_store = dict({kwargs['job_list_key']: []})
        self.job_list_key = kwargs['job_list_key']

    def add_job(self, job: dict):
        job_id = job['id']
        self.backing_store[job_id] = job
        self.list.append(job_id)
        return

    def remove_job(self, job_id: str):
        self.backing_store.pop(job_id)
        self.list.remove(job_id)
        return

    def get_job(self, job_id: str):
        job = self.backing_store.get(job_id)
        return job

    def update_job_value(self, job_id: str, key: str, value: str):
        self.backing_store[job_id][key] = value
        return

    def pop_job(self):
        if len(self.list) < 1:
            return None
        return self.list.pop(-1)

    @property
    def pending_jobs(self):
        return len(self.list)

    @property
    def list(self):
        return self.backing_store[self.job_list_key]


@pytest.fixture(scope='function')
def nginx_container(vars, network, printer, controller_container):
    """Run the nginx container.

    NGINX dies if upstream endpoint doesn't exist, so we required
    the controller container for this fixture."""

    controller_ready_string = b'Application startup complete.'
    start = datetime.now()
    now = datetime.now()

    while True:
        if (now - start) < timedelta(seconds=30):
            if controller_ready_string in controller_container.logs():
                break
        else:
            raise TimeoutError('controller container did not start in time')
        time.sleep(1)

    container = None
    image = None
    random_tag = datetime.now().strftime('%s')
    nginx_tag = f'{vars.NGINX_CUSTOM}:{random_tag}'
    d = docker.from_env()
    try:
        images = d.images.list()
        nginx_found = False
        # See if selenium image is already local
        for image in images:
            if vars.NGINX in image.tags:
                nginx_found = True
                break
        if not nginx_found:
            d.images.pull(vars. NGINX, )
        # Build renderer container


        # build up the path to the context and the path to the Dockerfile
        relative_context_path = pathlib.Path('render2/src/shared/')
        relative_docker_path = pathlib.Path('render2/src/renderer/Dockerfile')
        current_dir = pathlib.Path(os.getcwd())
        context_path = str(current_dir.joinpath(relative_context_path))
        docker_path = str(current_dir.joinpath(relative_docker_path))
        # context_path = get_abs_path_relative_to_ace(relative_context_path)
        # docker_path = get_abs_path_relative_to_ace(relative_docker_path)

        # This blocks until the container is built
        _ = d.images.build(path='render2/src/nginx', tag=nginx_tag, use_config_proxy=True)

        # Remove running or stopped containers that might be left behind from previously
        # failed tests. The container names will conflict with the new containers being
        # created.
        remove_existing_container(d, vars.NGINX_DNS_NAME)

        container = d.containers.run(
            nginx_tag,
            detach=True,
            network=network.name,
            ports={'8443/tcp': ('127.0.0.1', 8443)},
            environment={
                'NGINX_SERVER_NAME': vars.NGINX_DNS_NAME,
                'NGINX_X509_PRIVATE_KEY_B64': NGINX_TEST_KEY,
                'NGINX_X509_PUBLIC_CERT_B64': NGINX_TEST_CERT,
                'CLIENT_CERT_CA': NGINX_TEST_CA,
                'UVICORN_HOST': vars.CONTROLLER_DNS_NAME,
                'UVICORN_PORT': '8080'
            },
            name=vars.NGINX_DNS_NAME
        )
        time.sleep(10)  # Make sure the container has time to start up
        yield container
    finally:
        # If the container doesn't exist, the image might, so
        # go ahead and try to remove image even if the container
        # doesn't exist.
        try:
            container.reload()
            printer(f'Container status: {container.status}')
            printer(container.logs().decode('utf-8'))
            if container.status == 'running':
                container.stop()
            container.remove()
        except Exception:
            pass

        try:
            d.images.remove(nginx_tag)
        except Exception:
            pass

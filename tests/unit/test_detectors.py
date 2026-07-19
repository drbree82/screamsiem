from datetime import datetime, timezone
from screamsiem.detections.engine import DetectorEngine
from screamsiem.events import make_event

def test_new_listener_and_suspicious_path_are_critical():
    engine=DetectorEngine(); e=make_event("h","socket","new_listening_socket","python3 /tmp/update.py began listening on 0.0.0.0:4444",{"address":"0.0.0.0","port":4444,"pid":42,"command":"python3 /tmp/update.py"},"high")
    findings=engine.evaluate(e,{"listeners":[]})
    assert findings and findings[0].detector_id=="new_listener" and findings[0].severity=="critical"

def test_ssh_failure_threshold():
    engine=DetectorEngine(); result=[]
    for i in range(5):
        e=make_event("h","journal","ssh_auth_failure","failed",{"source_ip":"10.0.0.2"})
        result=engine.evaluate(e)
    assert any(x.detector_id=="ssh_failures" for x in result)

def test_listener_correlation_uses_endpoint_not_volatile_process_identity():
    engine=DetectorEngine()
    first=make_event("h","socket","new_listening_socket","listener",{"address":"0.0.0.0","port":8086,"pid":10,"process":"old"})
    second=make_event("h","socket","new_listening_socket","listener",{"address":"0.0.0.0","port":8086,"pid":11,"process":"new"})
    first_finding=engine.evaluate(first,{"listeners":[]})[0]
    second_finding=engine.evaluate(second,{"listeners":[]})[0]
    assert first_finding.correlation_key==second_finding.correlation_key

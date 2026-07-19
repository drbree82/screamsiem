from screamsiem.parsers.journal import parse_journal_line
from screamsiem.parsers.passwd import parse_passwd
from screamsiem.parsers.ps import parse_ps, process_fingerprint
from screamsiem.parsers.ss import parse_ss

def test_ps_parser_and_stable_fingerprint():
    a=parse_ps("8421 100 www-data 12 python3 python3 /tmp/update.py")[0]
    b=parse_ps("8422 100 www-data 2 python3 python3 /tmp/update.py")[0]
    assert a["pid"]==8421 and a["suspicious_path"]
    assert process_fingerprint(a)==process_fingerprint(b)

def test_ss_parser_ipv4_and_ipv6():
    text='''tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("python3",pid=8421,fd=3))\ntcp6 LISTEN 0 128 [::1]:22 [::]:* users:(("sshd",pid=11,fd=4))'''
    values=parse_ss(text,True)
    assert values[0]["port"]==4444 and values[0]["pid"]==8421
    assert values[1]["local_address"]=="::1" and values[1]["port"]==22

def test_journal_and_passwd_parsers():
    item=parse_journal_line('{"MESSAGE":"Failed password for root from 10.0.0.2","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"3"}')
    assert item["message"].startswith("Failed password") and item["unit"]=="sshd.service"
    users=parse_passwd("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin")
    assert users[0]["uid"]==0 and users[1]["interactive"] is False

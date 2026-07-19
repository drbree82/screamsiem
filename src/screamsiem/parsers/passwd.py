from __future__ import annotations


def parse_passwd(text: str) -> list[dict]:
    out=[]
    for line in text.splitlines():
        parts=line.split(":")
        if len(parts)!=7: continue
        try: uid=int(parts[2]); gid=int(parts[3])
        except ValueError: continue
        out.append({"name":parts[0],"uid":uid,"gid":gid,"gecos":parts[4],"home":parts[5],"shell":parts[6],"interactive":parts[6] not in {"/usr/sbin/nologin","/sbin/nologin","/bin/false"}})
    return out

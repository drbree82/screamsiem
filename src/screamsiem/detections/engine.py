from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..events import make_event
from ..models import Event, Finding
from ..parsers.ps import suspicious_path


class DetectorEngine:
    """Small deterministic ruleset. It returns findings; persistence is central."""

    def __init__(self, ssh_failure_threshold: int = 5):
        self.ssh_failure_threshold = ssh_failure_threshold
        self._ssh_failures: dict[tuple[str, str], list[datetime]] = {}
        self._seen_listeners: dict[str, set[str]] = {}

    def evaluate(self, event: Event, baseline: dict | None = None) -> list[Finding]:
        baseline=baseline or {}; out=[]
        if event.event_type in {"new_listening_socket", "listener_changed"}:
            listener_key=self._listener_key(event.data)
            known={self._listener_key(x) for x in baseline.get("listeners", [])}
            suspicious=bool(event.data.get("suspicious_path") or suspicious_path(str(event.data.get("command", ""))))
            if listener_key not in known:
                sev="critical" if suspicious or event.data.get("address") in {"0.0.0.0", "::"} else "medium"
                out.append(self._finding(event,"new_listener",f"new-listener:{listener_key}",sev,"Unexpected listening socket",f"{event.summary}"))
        if event.event_type in {"process_started", "process_snapshot"}:
            command=str(event.data.get("command", "")); executable=str(event.data.get("executable", ""))
            if suspicious_path(command) or executable.startswith(("/tmp/","/var/tmp/","/dev/shm/")) or event.data.get("deleted_executable"):
                out.append(self._finding(event,"suspicious_path",f"suspicious-process:{event.data.get('pid')}:{event.data.get('start_time', '')}","high","Suspicious executable path",f"{command or executable} is executing from a temporary or deleted path."))
        if event.event_type in {"ssh_auth_failure", "authentication_failure"}:
            source=str(event.data.get("source_ip", "unknown")); key=(event.host_id,source); now=event.observed_at
            values=[x for x in self._ssh_failures.get(key,[]) if now-x <= timedelta(minutes=2)]; values.append(now); self._ssh_failures[key]=values
            if len(values)>=self.ssh_failure_threshold:
                out.append(self._finding(event,"ssh_failures",f"ssh-failures:{source}","high","Repeated SSH authentication failures",f"{len(values)} SSH authentication failures from {source} in two minutes."))
        if event.event_type in {"new_service", "changed_service", "failed_service"}:
            out.append(self._finding(event,"systemd_change",f"service:{event.data.get('unit')}:{event.event_type}","high" if event.event_type!="failed_service" else "medium","Systemd service changed",event.summary))
        if event.event_type in {"new_privileged_user", "uid_zero_added"}:
            out.append(self._finding(event,"privileged_user",f"uid-zero:{event.data.get('name')}","critical","Unexpected privileged user",event.summary))
        if event.event_type in {"telemetry_loss", "collector_stopped", "ssh_disconnected"}:
            out.append(self._finding(event,"telemetry_loss",f"telemetry:{event.data.get('collector', event.event_type)}","high","Host telemetry degraded",event.summary))
        return out

    @staticmethod
    def _listener_key(data: dict) -> str:
        # Process names/PIDs are often hidden from an unprivileged `ss -p`
        # invocation and PIDs can change when a service restarts. The socket
        # endpoint is the stable identity for listener correlation.
        return f"{data.get('protocol','tcp')}|{data.get('address',data.get('local_address',''))}|{data.get('port')}"

    @staticmethod
    def listener_correlation(data: dict) -> str:
        return "new-listener:" + DetectorEngine._listener_key(data)

    @staticmethod
    def _finding(event: Event, detector: str, correlation: str, severity: str, title: str, summary: str) -> Finding:
        now=event.observed_at
        return Finding(id="fnd_"+event.fingerprint.split(":")[-1][:24],host_id=event.host_id,detector_id=detector,correlation_key=correlation,state="new",severity=severity,confidence=0.8 if severity in {"high","critical"} else 0.6,title=title,machine_summary=summary,first_seen_at=now,last_seen_at=now,updated_at=now,event_ids=[event.id])

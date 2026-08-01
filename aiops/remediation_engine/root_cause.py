from __future__ import annotations
import re
from typing import Any
from .models import RootCause

_ALIASES = {
"kubepodcrashlooping":"CrashLoopBackOff","crashloop":"CrashLoopBackOff","crashloopbackoff":"CrashLoopBackOff",
"oomkilled":"OOMKilled","containeroomkilled":"OOMKilled","kubepodcontaineroomkilled":"OOMKilled",
"imagepullbackoff":"ImagePullBackOff","errimagepull":"ImagePullBackOff","kubeimagepullbackoff":"ImagePullBackOff",
"highcpu":"HighCPUUsage","highcpuusage":"HighCPUUsage","cpuhigh":"HighCPUUsage",
"highmemory":"HighMemoryUsage","highmemoryusage":"HighMemoryUsage","memoryhigh":"HighMemoryUsage",
"podpending":"PodPending","kubepodnotready":"PodPending",
"deploymentfailed":"DeploymentFailed","kubedeploymentreplicasmismatch":"DeploymentFailed",
"diskpressure":"DiskPressure","nodenotready":"NodeNotReady","nodedown":"NodeNotReady",
"secretmissing":"SecretMissing","secretnotfound":"SecretMissing","configmapmissing":"SecretMissing",
"databaseconnection":"DatabaseConnection","databaseconnectionfailure":"DatabaseConnection",
"dnsfailure":"DNSFailure","dnsresolutionfailure":"DNSFailure",
"kafkafailure":"KafkaFailure","kafkabrokerunavailable":"KafkaFailure",
"networklatency":"NetworkLatency","highlatency":"NetworkLatency",
"certificateexpired":"CertificateExpired",
}

def normalize_alert(value: Any) -> str:
    raw = str(value or "Unknown").strip()
    key = "".join(ch for ch in raw.lower() if ch.isalnum())
    return _ALIASES.get(key, raw)

def _flatten(value: Any) -> str:
    if isinstance(value, dict): return " ".join(f"{k} {_flatten(v)}" for k,v in value.items())
    if isinstance(value, (list,tuple,set)): return " ".join(_flatten(v) for v in value)
    return str(value or "")

def resolve_root_cause(incident: dict[str, Any]) -> RootCause:
    text = _flatten(incident).lower()
    rules = [
        ("OOMKilled", ("oomkilled",), r"exit(?:_|\s*)code\D*137\b"),
        ("ImagePullBackOff", ("imagepullbackoff","errimagepull","failed to pull image"), None),
        ("SecretMissing", ("secret not found","secret does not exist","failedmount"), None),
        ("CertificateExpired", ("certificate has expired","certificate expired"), None),
        ("DNSFailure", ("no such host","dns resolution failed"), None),
        ("KafkaFailure", ("kafka broker unreachable","leader not available"), None),
        ("DatabaseConnection", ("unable to connect to postgresql","database connection refused"), None),
        ("NodeNotReady", ("node status changed to notready","node not ready"), None),
        ("DiskPressure", ("node has disk pressure","diskpressure"), None),
    ]
    for name, phrases, pattern in rules:
        if any(p in text for p in phrases) or (pattern and re.search(pattern,text)):
            return RootCause(name, .99, (f"deterministic evidence matched {name}",))
    alert = normalize_alert(incident.get("alert") or incident.get("alert_name"))
    return RootCause(alert, .85, (f"normalized alert name: {alert}",))

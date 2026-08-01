from __future__ import annotations
import json, os, subprocess
from pathlib import Path
from typing import Any
import requests, yaml
from .evidence_resolver import EvidenceResolutionError
from .models import DerivedValue, Target
from .operation_builder import pointer_get

def _walk(value: Any):
    if isinstance(value, dict):
        for k,v in value.items():
            yield str(k),v
            yield from _walk(v)
    elif isinstance(value,list):
        for item in value: yield from _walk(item)

def _find_first(data: Any, names: set[str]) -> Any:
    wanted={n.lower() for n in names if n}
    for key,value in _walk(data):
        if key.lower() in wanted and value not in (None,"",[],{}): return value
    return None

class CompositeEvidenceProvider:
    """Authoritative resolver. It never contains literal remediation values."""
    def __init__(self, *, incident: dict[str,Any], manifest_path: Path, manifest: dict[str,Any]):
        self.incident=incident; self.manifest_path=manifest_path; self.manifest=manifest
    def get(self, source: str, query: dict[str,Any], target: Target) -> DerivedValue:
        handler={"incident":self._incident,"manifest":self._manifest,"prometheus":self._prometheus,"kubernetes":self._kubernetes,"git_history":self._git_history,"replicaset_history":self._git_history,"scheduler":self._scheduler}.get(source)
        if handler is None: raise EvidenceResolutionError(f"unsupported authoritative source: {source}")
        return handler(query,target)
    def _incident(self, query, target):
        key=str(query.get("key") or query.get("selector") or query.get("metric") or "")
        value=_find_first(self.incident,{key})
        if value is None: raise EvidenceResolutionError(f"incident evidence unavailable: {key}")
        return DerivedValue(value,"incident",{"key":key})
    def _manifest(self, query, target):
        selector=str(query.get("selector") or query.get("key") or "")
        path=selector.replace("{container}",str(self._container_index(target)))
        exists,value=pointer_get(self.manifest,path)
        if not exists: raise EvidenceResolutionError(f"manifest selector unavailable: {path}")
        return DerivedValue(value,"manifest",{"path":path})
    def _container_index(self,target):
        containers=self.manifest.get("spec",{}).get("template",{}).get("spec",{}).get("containers",[])
        matches=[i for i,c in enumerate(containers) if isinstance(c,dict) and c.get("name")==target.container]
        if len(matches)!=1: raise EvidenceResolutionError("container could not be resolved uniquely")
        return matches[0]
    def _prometheus(self, query, target):
        metric=str(query.get("metric") or "")
        collected=_find_first(self.incident,{metric})
        if collected is not None: return DerivedValue(collected,"prometheus",{"metric":metric,"mode":"collected"})
        history=self.incident.get("prometheus_history") or self.incident.get("historical_summary") or {}
        aliases={
          "container_memory_observed_mib":{"maximum_mib","historical_max_memory_mib"},
          "container_cpu_observed_millicores":{"maximum_millicores","historical_max_cpu_millicores"},
          "latency_based_replica_recommendation":{"recommended_replicas","desired_replicas"},
        }
        value=_find_first(history,aliases.get(metric,{metric}))
        if value is not None: return DerivedValue(value,"prometheus",{"metric":metric,"mode":"history"})
        base=os.getenv("PROMETHEUS_URL","http://localhost:9090").rstrip("/")
        expressions={
          "container_memory_observed_mib":f'max_over_time(container_memory_working_set_bytes{{namespace="{target.namespace}",container="{target.container or ""}"}}[1h]) / 1024 / 1024',
          "container_cpu_observed_millicores":f'max_over_time(rate(container_cpu_usage_seconds_total{{namespace="{target.namespace}",container="{target.container or ""}"}}[5m])[1h:5m]) * 1000',
        }
        expr=expressions.get(metric)
        if not expr: raise EvidenceResolutionError(f"no Prometheus resolver for metric: {metric}")
        try:
            response=requests.get(f"{base}/api/v1/query",params={"query":expr},timeout=10);response.raise_for_status()
            raw=response.json()["data"]["result"][0]["value"][1]
            return DerivedValue(float(raw),"prometheus",{"metric":metric,"query":expr})
        except Exception as exc: raise EvidenceResolutionError(f"Prometheus evidence unavailable for {metric}: {exc}") from exc
    def _kubectl(self,args):
        try:
            cp=subprocess.run(["kubectl",*args,"-o","json"],check=True,capture_output=True,text=True,timeout=20)
            return json.loads(cp.stdout)
        except Exception as exc: raise EvidenceResolutionError(f"Kubernetes evidence unavailable: {exc}") from exc
    def _kubernetes(self,query,target):
        selector=str(query.get("selector") or "")
        collected=_find_first(self.incident,{selector})
        if collected is not None: return DerivedValue(collected,"kubernetes",{"selector":selector,"mode":"collected"})
        if selector=="desired_replicas_from_hpa":
            data=self._kubectl(["get","hpa","-n",target.namespace])
            values=[]
            for item in data.get("items",[]):
                ref=item.get("spec",{}).get("scaleTargetRef",{})
                if ref.get("name")==target.name and item.get("status",{}).get("desiredReplicas") is not None: values.append(int(item["status"]["desiredReplicas"]))
            if len(values)==1:return DerivedValue(values[0],"kubernetes",{"selector":selector})
        raise EvidenceResolutionError(f"Kubernetes selector could not be resolved safely: {selector}")
    def _repo_root(self):
        repo=self.manifest_path.parent
        while repo!=repo.parent and not (repo/".git").exists(): repo=repo.parent
        if not (repo/".git").exists(): raise EvidenceResolutionError("Git repository root could not be found")
        return repo
    def _historical_doc(self):
        repo=self._repo_root(); rel=self.manifest_path.relative_to(repo).as_posix()
        try:
            log=subprocess.run(["git","-C",str(repo),"log","--format=%H","--",rel],check=True,capture_output=True,text=True,timeout=20).stdout.splitlines()
            for revision in log[1:20]:
                text=subprocess.run(["git","-C",str(repo),"show",f"{revision}:{rel}"],check=True,capture_output=True,text=True,timeout=20).stdout
                for doc in yaml.safe_load_all(text):
                    if isinstance(doc,dict) and doc.get("kind")==self.manifest.get("kind") and doc.get("metadata",{}).get("name")==self.manifest.get("metadata",{}).get("name"): return revision,doc
        except Exception as exc: raise EvidenceResolutionError(f"Git history unavailable: {exc}") from exc
        raise EvidenceResolutionError("No earlier matching manifest exists in Git history")
    def _git_history(self,query,target):
        selector=str(query.get("selector") or ""); revision,doc=self._historical_doc()
        containers=doc.get("spec",{}).get("template",{}).get("spec",{}).get("containers",[])
        matches=[c for c in containers if isinstance(c,dict) and c.get("name")==target.container]
        if len(matches)!=1: raise EvidenceResolutionError("historical container could not be resolved uniquely")
        mapping={"last_successful_container_image":"image","last_successful_container_command":"command","last_successful_container_args":"args"}
        field=mapping.get(selector)
        if not field or field not in matches[0]: raise EvidenceResolutionError(f"Git history selector unavailable: {selector}")
        return DerivedValue(matches[0][field],"git_history",{"selector":selector,"revision":revision})
    def _scheduler(self,query,target):
        selector=str(query.get("selector") or ""); value=_find_first(self.incident,{selector})
        if value is None: raise EvidenceResolutionError(f"scheduler evidence unavailable: {selector}")
        return DerivedValue(value,"scheduler",{"selector":selector})

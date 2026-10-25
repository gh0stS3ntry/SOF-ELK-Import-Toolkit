"""Explicit index templates for the toolkit's custom-artifact indexes.

The JSON files live in Windows/index_templates/:
  component-toolkit-common.json  fields every custom-artifact index shares (host, case, kape.*, file.*)
  index-<artifact>.json          one index template per artifact, composed of the common component

Importers install both templates before loading (so any <artifact>-* index gets the same schema,
whoever creates it) and also create their target index with the merged body, so an --index
override that does not match <artifact>-* still gets the fixed mapping.
"""
import copy
import json
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "index_templates"
COMMON_NAME = "sofelk-toolkit-common"


def _load(stem):
    path = TEMPLATE_DIR / f"{stem}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Cannot read index template {path}: {exc}")


def _merge(base, extra):
    """Deep merge: dicts merge key by key, lists concatenate, anything else is replaced."""
    out = copy.deepcopy(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + copy.deepcopy(v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load(artifact):
    """(component, index_template, merged) for an artifact such as 'amcache'.
    merged is {"settings": ..., "mappings": ...}, ready to PUT as an index body."""
    component = _load("component-toolkit-common")
    index_tpl = _load(f"index-{artifact}")
    merged = _merge(component.get("template", {}), index_tpl.get("template", {}))
    return component, index_tpl, merged


def field_types(mappings):
    """Flatten mapping properties to {"dotted.field": "type"} (leaf fields only)."""
    out = {}

    def walk(props, prefix):
        for name, spec in props.items():
            path = f"{prefix}{name}"
            if "properties" in spec:
                walk(spec["properties"], path + ".")
            else:
                out[path] = spec.get("type", "object")

    walk(mappings.get("properties", {}), "")
    return out


def install(es_call, artifact, component, index_tpl):
    """PUT the common component template and the artifact's index template.
    es_call(method, path, body) -> (status, response). Exits on failure."""
    for path, body in ((f"/_component_template/{COMMON_NAME}", component),
                       (f"/_index_template/sofelk-toolkit-{artifact}", index_tpl)):
        status, resp = es_call("PUT", path, json.dumps(body))
        if status >= 300:
            raise SystemExit(f"Could not install template {path} ({status}): {json.dumps(resp)[:500]}")

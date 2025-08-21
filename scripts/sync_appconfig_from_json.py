#!/usr/bin/env python3
import os, re, sys, json, subprocess, argparse
from typing import Any, Dict

KVREF_RE = re.compile(r"^https://[^.]+\.vault\.azure\.net/secrets/[^/]+(/[^/]+)?$")

def sh(cmd: list[str]) -> None:
    print("+", " ".join(subprocess.list2cmdline([c]) for c in cmd))
    subprocess.check_call(cmd)

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def build_context(vars_json: Dict[str, Any]) -> Dict[str, Any]:
    ctx = dict(vars_json)

    # Overlay environment overrides (e.g., GH secrets/vars with same names)
    for k, v in os.environ.items():
        # Keep booleans if original is bool and env provides "true"/"false"
        if k in ctx and isinstance(ctx[k], bool):
            ctx[k] = (v.lower() == "true")
        else:
            ctx[k] = v

    # Derive UNC_BASE if not provided
    if "UNC_BASE" not in ctx:
        acct = ctx.get("STORAGE_ACCOUNT", "")
        share = ctx.get("SHARE_USERCONTENT", "usercontent")
        if acct:
            ctx["UNC_BASE"] = f"\\\\{acct}.file.core.windows.net\\{share}"
        else:
            ctx["UNC_BASE"] = f"\\\\.invalid\\{share}"

    return ctx

def render_value(node: Any, ctx: Dict[str, Any]) -> Any:
    """ Recursively render:
        - If node is a string == ${VAR} -> return ctx[VAR] as-is (preserve type)
        - If node is a string containing ${VAR} -> string replace with str(ctx[VAR])
        - If dict/list -> recurse
    """
    if isinstance(node, str):
        m = re.fullmatch(r"\$\{([A-Z0-9_]+)\}", node)
        if m:
            key = m.group(1)
            return ctx.get(key, "")
        # partial substitution
        def repl(match):
            key = match.group(1)
            return str(ctx.get(key, ""))
        return re.sub(r"\$\{([A-Z0-9_]+)\}", repl, node)

    if isinstance(node, dict):
        return {k: render_value(v, ctx) for k, v in node.items()}

    if isinstance(node, list):
        return [render_value(v, ctx) for v in node]

    return node

def push_json_key(cs: str, key: str, label: str | None, value_obj: Any):
    value_str = json.dumps(value_obj, separators=(",", ":"))
    cmd = ["az", "appconfig", "kv", "set", "--connection-string", cs, "--key", key,
           "--value", value_str, "--content-type", "application/json", "--yes"]
    if label:
        cmd.extend(["--label", label])
    sh(cmd)

def push_string_key(cs: str, key: str, label: str | None, value_str: str):
    cmd = ["az", "appconfig", "kv", "set", "--connection-string", cs, "--key", key,
           "--value", value_str, "--content-type", "text/plain", "--yes"]
    if label:
        cmd.extend(["--label", label])
    sh(cmd)

def push_kvref(cs: str, key: str, label: str | None, secret_id: str):
    if not KVREF_RE.match(secret_id):
        raise ValueError(f"Invalid Key Vault secret identifier for {key}: {secret_id}")
    cmd = ["az", "appconfig", "kv", "set-keyvault", "--connection-string", cs,
           "--key", key, "--secret-identifier", secret_id, "--yes"]
    if label:
        cmd.extend(["--label", label])
    sh(cmd)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--connection-string", required=True)
    p.add_argument("--features", default="config/features.json")
    p.add_argument("--vars", required=True)  # e.g., config/variables.dev.json
    p.add_argument("--label", default=None)  # leave empty for no label
    args = p.parse_args()

    cs = args.connection_string
    if not cs:
        sys.exit("APPCONFIG connection string is required")

    features = load_json(args.features)
    vars_json = load_json(args.vars)
    ctx = build_context(vars_json)

    # Use explicit label arg; fallback to context TARGET_LABEL; allow _NO_LABEL_
    label = args.label if args.label is not None else ctx.get("TARGET_LABEL")
    if label == "_NO_LABEL_":
        label = None

    for entry in features.get("features", []):
        key = entry["key"]
        ftype = entry.get("type", "json")

        if ftype == "json":
            template = entry["template"]
            value_obj = render_value(template, ctx)
            print(f"Setting JSON key: {key} (label={label}) -> {value_obj}")
            push_json_key(cs, key, label, value_obj)

        elif ftype == "string":
            raw = entry["value"]
            value = render_value(raw, ctx)
            value_str = value if isinstance(value, str) else str(value)
            print(f"Setting string key: {key} (label={label}) -> {value_str}")
            push_string_key(cs, key, label, value_str)

        elif ftype == "kvref":
            var_name = entry["secretVar"]
            secret_id = ctx.get(var_name, "")
            if not secret_id:
                print(f"Skipping {key}: {var_name} is empty (no secret set).")
                continue
            print(f"Setting KV reference: {key} (label={label}) -> {var_name}")
            push_kvref(cs, key, label, secret_id)

        else:
            print(f"Unknown type '{ftype}' for key {key}; skipping.")

if __name__ == "__main__":
    main()

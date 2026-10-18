"""The evidence store: one folder per run, one JSON file per app.

No database. A run is a folder, an app is a file, a fact is a key. Fifty apps give a few
thousand facts, which fits in a few megabytes of JSON that rg, jq and git diff can read.

    data/runs/<id>/run.json          device, target list hash, dataset versions, checks, log
    data/runs/<id>/apps/<pkg>.json   app info plus a map of facts

A fact is 'kind:name -> {value, tier, source, confidence, at}'. The keys are flat and the values
can be compared, so a diff between two runs is a key and value comparison.
"""
import hashlib
import json
import os
import re
import tempfile
import time

from . import paths

TIERS = ("T0", "T1", "T2", "T3", "T4")
SUBJECT = re.compile(r"^[a-z][a-z0-9-]*(:[^\s]+)+$")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_run_id():
    return time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())


def targets_sha256(packages):
    return hashlib.sha256(chr(10).join(sorted(packages)).encode()).hexdigest()


# --- reading and writing ------------------------------------------------------------

def _read_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path, doc):
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write(chr(10))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def run_ids():
    root = paths.runs()
    if not os.path.isdir(root):
        return []
    return sorted(d for d in os.listdir(root)
                  if os.path.isfile(os.path.join(root, d, "run.json")))


def latest():
    """The run that commands read by default."""
    marker = paths.latest_file()
    if os.path.exists(marker):
        with open(marker, encoding="utf-8") as f:
            rid = f.read().strip()
        if rid and os.path.exists(paths.run_file(rid)):
            return rid
    ids = run_ids()
    return ids[-1] if ids else None


def set_latest(rid):
    with open(paths.latest_file(), "w", encoding="utf-8") as f:
        f.write(rid + chr(10))


def start_run(tool_version, device=None, note=None, rid=None):
    """Create a run directory. One run is one pass over the phone; phases fill it in."""
    rid = rid or new_run_id()
    os.makedirs(paths.apps_dir(rid), exist_ok=True)
    doc = {
        "id": rid,
        "tool": tool_version,
        "started_at": now(),
        "finished_at": None,
        "note": note,
        "device": device or {},
        "targets_sha256": None,
        "apps": [],
        "datasets": {},
        "gates": {},
        "log": [],
    }
    save_run(rid, doc)
    set_latest(rid)
    return rid


def resolve(rid=None):
    rid = rid or latest()
    if not rid:
        raise SystemExit("no run yet; start one with: uv run locaudit capture")
    if not os.path.exists(paths.run_file(rid)):
        raise SystemExit(f"no run {rid!r} under {paths.runs()}")
    return rid


def load_run(rid=None):
    return _read_json(paths.run_file(resolve(rid)))


def save_run(rid, doc):
    _write_json(paths.run_file(rid), doc)


def update_run(rid, fn):
    doc = load_run(rid)
    fn(doc)
    save_run(rid, doc)
    return doc


def apps(rid=None):
    """Every app fact sheet in a run, sorted by package."""
    root = paths.apps_dir(resolve(rid))
    if not os.path.isdir(root):
        return []
    return [_read_json(os.path.join(root, name))
            for name in sorted(os.listdir(root)) if name.endswith(".json")]


def load_app(pkg, rid=None):
    return _read_json(paths.app_file(resolve(rid), pkg))


def save_app(pkg, doc, rid=None):
    rid = resolve(rid)
    errors = validate_app(doc)
    if errors:
        raise ValueError(f"{pkg}: " + "; ".join(errors))
    _write_json(paths.app_file(rid, pkg), doc)
    run = load_run(rid)
    if pkg not in run["apps"]:
        run["apps"].append(pkg)
        run["apps"].sort()
        save_run(rid, run)
    return doc


def new_app(pkg, rid=None):
    return {"pkg": pkg, "run": resolve(rid), "app": {}, "facts": {}}


def update_app(pkg, fn, rid=None, app=None):
    """Read, mutate, write. `fn` receives the fact-sheet dict and returns it."""
    doc = load_app(pkg, rid) or new_app(pkg, rid)
    if app:
        doc["app"].update(app)
    fn(doc)
    return save_app(pkg, doc, rid)


# --- facts --------------------------------------------------------------------------

def add_fact(doc, subject, value, *, tier, source, confidence="certain", **extra):
    """Record one fact. The subject is the identity, the value is what a diff compares."""
    if tier not in TIERS:
        raise ValueError(f"{subject}: tier must be one of {TIERS}, not {tier!r}")
    if not SUBJECT.match(subject):
        raise ValueError(f"bad subject {subject!r}: expected kind:detail")
    record = {"value": value, "tier": tier, "source": source,
              "confidence": confidence, "at": now()}
    record.update({k: v for k, v in extra.items() if v is not None})
    doc["facts"][subject] = record
    return record


def fact(doc, subject, default=None):
    return (doc.get("facts") or {}).get(subject, default)


def by_kind(doc):
    """Facts grouped by namespace prefix, for display."""
    groups = {}
    for subject, value in sorted((doc.get("facts") or {}).items()):
        groups.setdefault(subject.split(":", 1)[0], {})[subject] = value
    return groups


# --- gates and the log --------------------------------------------------------------

class GateFailed(Exception):
    pass


def set_gate(rid, phase, ok, summary):
    def mutate(doc):
        doc["gates"][phase] = {"ok": bool(ok), "summary": summary, "at": now()}
    update_run(rid, mutate)
    return bool(ok)


def gate_ok(run_doc, phase):
    gate = (run_doc.get("gates") or {}).get(phase)
    return bool(gate and gate.get("ok"))


def require(rid, phase, ok, summary):
    """Record and enforce. A failed gate raises, so it cannot be stepped over."""
    set_gate(rid, phase, ok, summary)
    if not ok:
        raise GateFailed(f"{phase}: {summary}")
    return summary


# --- validation ---------------------------------------------------------------------

def validate_app(doc):
    """What a fact sheet must satisfy to be written at all."""
    errors = []
    if not doc.get("pkg"):
        errors.append("missing pkg")
    if not doc.get("run"):
        errors.append("missing run")
    facts = doc.get("facts")
    if not isinstance(facts, dict):
        return errors + ["facts must be an object"]
    for subject, record in facts.items():
        if not SUBJECT.match(subject):
            errors.append(f"{subject}: expected kind:detail")
        if not isinstance(record, dict):
            errors.append(f"{subject}: fact must be an object")
            continue
        if record.get("tier") not in TIERS:
            errors.append(f"{subject}: tier must be one of {TIERS}")
        if not record.get("source"):
            errors.append(f"{subject}: missing source")
        if "value" not in record:
            errors.append(f"{subject}: missing value")
    return errors


def validate_run(doc):
    errors = []
    for key in ("id", "tool", "started_at", "apps", "gates"):
        if key not in doc:
            errors.append(f"missing {key}")
    if not isinstance(doc.get("gates"), dict):
        errors.append("gates must be an object")
    return errors


# --- the diff -----------------------------------------------------------------------

def diff_facts(old, new):
    """Added, removed and changed facts between two versions of one app."""
    a = (old or {}).get("facts") or {}
    b = (new or {}).get("facts") or {}
    return {
        "added": {k: b[k] for k in sorted(set(b) - set(a))},
        "removed": {k: a[k] for k in sorted(set(a) - set(b))},
        "changed": {k: {"from": a[k], "to": b[k]} for k in sorted(set(a) & set(b))
                    if (a[k].get("value"), a[k].get("confidence"))
                    != (b[k].get("value"), b[k].get("confidence"))},
    }

"""Every path the tool writes. One module, so nothing guesses a directory.

Workspace layout (see docs/00-README.md):

    data/device/            raw dumps, the privacy boundary
    data/apks/<pkg>/        base.apk plus every split, verifiable
    data/cache/<pkg>/       derived bulk: tokens.gz, domains.gz, manifest.xml
    data/refdata/           downloaded lists plus versions.json
    data/runs/<id>/         run.json and apps/<pkg>.json  <- the audit
    data/runs/LATEST        one line: the run id to read by default
    data/reports/           exports and findings.md
"""
import os

PKG_ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(PKG_ROOT)


def home():
    """Audit workspace root. LOCAUDIT_HOME wins, then the current directory."""
    return os.path.abspath(os.environ.get("LOCAUDIT_HOME") or os.getcwd())


def data(*parts):
    return os.path.join(home(), "data", *parts)


def device(*parts):
    return data("device", *parts)


def dumpsys(*parts):
    return data("device", "dumpsys_package", *parts)


def apks(pkg=None):
    return data("apks", pkg) if pkg else data("apks")


def cache(pkg=None):
    return data("cache", pkg) if pkg else data("cache")


def refdata(*parts):
    return data("refdata", *parts)


def reports(*parts):
    return data("reports", *parts)


def tmp(*parts):
    return data("tmp", *parts)


def runs(rid=None):
    return data("runs", rid) if rid else data("runs")


def run_file(rid):
    return os.path.join(runs(rid), "run.json")


def apps_dir(rid):
    return os.path.join(runs(rid), "apps")


def app_file(rid, pkg):
    return os.path.join(apps_dir(rid), pkg + ".json")


def latest_file():
    return os.path.join(runs(), "LATEST")


DIRS = (
    ("data",),
    ("data", "device"),
    ("data", "device", "dumpsys_package"),
    ("data", "apks"),
    ("data", "cache"),
    ("data", "refdata"),
    ("data", "reports"),
    ("data", "tmp"),
    ("data", "decompiled"),
    ("data", "runs"),
)


def ensure():
    for parts in DIRS:
        os.makedirs(os.path.join(home(), *parts), exist_ok=True)
    return home()

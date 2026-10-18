"""What each maker says on the app's Play page that it collects and shares.

Needs the network, and only for the apps named (docs/commands/page.md). Three things are kept,
each smaller than the last:

    data/cache/<pkg>/datasafety.html   the page as it arrived, so nothing is re-asked for
    data/cache/<pkg>/datasafety.txt    the quote: the data safety part, one line per item
    data/runs/<id>/apps/<pkg>.json     the facts, which are what a report reads

The quote is the work product. Everything after the download reads it, so the parser can be
re-tested on the pages already on disk, and a person can check a claim against it in a few seconds.

The page is a web page, not an API (docs/reference/pitfalls.md#scraping-is-not-an-api). The reading
below keys on what the page says structurally - heading levels and their order - and not on CSS
class names, which are obfuscated, nor on the exact wording of a heading, which can change. A page
that does not hold that structure is written down as unknown in the page's own words, never as
"collects nothing".
"""
import hashlib
import html.parser
import json
import os
import re
import time
import urllib.error
import urllib.request

from . import paths, store

URL = "https://play.google.com/store/apps/datasafety?id={pkg}&hl=en"
AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) locaudit/0.1"
PAUSE = 2.0            # seconds between two requests: once per app, and not a bulk crawl
MAX_AGE_DAYS = 7       # a kept page older than this is asked for again
TIMEOUT = 30
PARSER = "2026-10-18.2"  # the reading below, by date: a fact records which one produced it

PLAY = "com.android.vending"

HEADING = "Data safety"
LOCATION = "Location"
LOCATION_TYPES = ("Precise location", "Approximate location")

# Google Play's own list of purposes. Matched as whole phrases, because one of them holds commas of
# its own: "Fraud prevention, security, and compliance".
PURPOSES = ("App functionality", "Analytics", "Developer communications",
            "Advertising or marketing", "Fraud prevention, security, and compliance",
            "Personalization", "Account management")

# The two sections that answer the question, in the order they appear. Taking them by place on the
# page means a change of wording does not break the reading. The security practices that follow are
# not read: they say nothing about location, and reading to the end of the page picks up the footer.
SECTIONS = ("shared", "collected")

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr"}

# Elements whose text is not page content: script blobs, styles, and the two icon words Play puts
# beside a collapsed panel.
SKIP = {"script", "style", "noscript", "template"}
NOISE = {"expand_more", "info", "Learn more", "· Optional", "Optional"}

OWNED = ("datasafety:collected:location", "datasafety:shared:location",
         "datasafety:purposes:location", "datasafety:fetched", "unknown:datasafety")


# --- the page as a tree -------------------------------------------------------------

class _Node:
    """One element: its tag, its own text, and its children. No class names, no attributes."""

    __slots__ = ("tag", "children", "parts")

    def __init__(self, tag):
        self.tag = tag
        self.children = []
        self.parts = []

    def own_text(self):
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()

    def text(self):
        joined = " ".join(self.parts + [child.text() for child in self.children])
        return re.sub(r"\s+", " ", joined).strip()

    def has_heading(self):
        return any(child.tag in ("h1", "h2", "h3", "h4") or child.has_heading()
                   for child in self.children)


class _Tree(html.parser.HTMLParser):
    """A page as elements, with the text kept where it sits."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("root")
        self.stack = [self.root]
        self.skipping = 0

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skipping += 1
            return
        if self.skipping:
            return
        node = _Node(tag)
        self.stack[-1].children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack[-1].tag == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag in SKIP:
            self.skipping = max(0, self.skipping - 1)
            return
        if self.skipping:
            return
        for depth in range(len(self.stack) - 1, 0, -1):
            if self.stack[depth].tag == tag:
                del self.stack[depth:]
                return

    def handle_data(self, data):
        if self.skipping or not data.strip():
            return
        self.stack[-1].parts.append(data.strip())


def tree_of(markup):
    parser = _Tree()
    parser.feed(markup)
    parser.close()
    return parser.root


def _order(node):
    """Every element in the order it appears on the page."""
    for child in node.children:
        yield child
        yield from _order(child)


def _purpose_words(text):
    """The purposes named in a line, as whole phrases. A line naming none names no purpose."""
    return [purpose for purpose in PURPOSES if purpose in text]


HEADINGS = ("h1", "h2", "h3", "h4")


def _pieces(nodes):
    """Every run of text in page order, as (element, its own words).

    An element's own words only, never its children's: a wrapper element can span a section
    boundary when the page nests its divs badly, and reading its whole text would pull the next
    section into this one.
    """
    for node in nodes:
        own = node.own_text()
        if own:
            yield node, own
        if node.children:
            yield from _pieces(node.children)


def _is_noise(text):
    return (text in NOISE or text.startswith("Learn more") or text.startswith("·")
            or (text.startswith("Data ") and "purpose" in text))


def _sentence(pieces):
    """The page's own first full sentence after the heading, with the 'Learn more' link cut off."""
    for _, text in pieces:
        text = text.split(" Learn more")[0].strip()
        if len(text) > 25 and not text.lower().startswith("learn more"):
            return text
    return ""


def read_page(markup):
    """The data safety answer for one page, in structure rather than in lines of text.

    Returns None when the page holds no data safety heading at all, and {"no_section": sentence}
    when it holds the heading but no section under it.

    Everything is done on one flat list of text pieces in page order. The page nests its divs badly
    in places, so an element's position in the tree is not its position in the document: cutting a
    section by tree position pulled the next section's text into it on one page.
    """
    pieces = list(_pieces([tree_of(markup)]))
    anchor = next((i for i, (node, text) in enumerate(pieces)
                   if node.tag in ("h1", "h2") and text == HEADING), None)
    if anchor is None:
        return None
    after = pieces[anchor + 1:]
    heads = [i for i, (node, _) in enumerate(after) if node.tag == "h2"]
    if not heads:
        return {"no_section": _sentence(after)
                or "the page says nothing about collected or shared data"}

    out = {"sections": {}}
    for place in range(min(len(heads), len(SECTIONS))):
        start = heads[place]
        end = heads[place + 1] if place + 1 < len(heads) else len(after)
        out["sections"][SECTIONS[place]] = _category(after[start + 1:end])
    return out


def _category(pieces):
    """One category of a section: which kinds of data, and for what purpose."""
    start = next((i for i, (node, text) in enumerate(pieces)
                  if node.tag == "h3" and text == LOCATION), None)
    if start is None:
        return {"present": False, "types": [], "purposes": []}
    end = next((i for i in range(start + 1, len(pieces))
                if pieces[i][0].tag in ("h2", "h3")), len(pieces))
    types, purposes = [], []
    waiting = False
    for _, text in pieces[start + 1:end]:
        if _is_noise(text):
            continue
        named_types = sorted((kind for kind in LOCATION_TYPES if kind in text),
                             key=text.index)
        if named_types:
            for found_type in named_types:
                if found_type not in types:
                    types.append(found_type)
            waiting = True
            continue
        if waiting:
            # The element under a data type holds that type's purposes: "App functionality".
            named = _purpose_words(text)
            if named:
                for purpose in named:
                    if purpose not in purposes:
                        purposes.append(purpose)
                waiting = False
    return {"present": True, "types": types, "purposes": purposes}


# --- the quote ----------------------------------------------------------------------

def quote_of(pkg, page, found):
    """The small text file that stands for the page from now on: what it said, app by app."""
    lines = [f"# what the Play page said on {page['meta']['fetched_at']}",
             f"# {page['meta']['url']}",
             f"pkg: {pkg}"]
    if found is None:
        lines.append("not-a-data-safety-page")
        return "\n".join(lines) + "\n"
    if found.get("no_section"):
        lines += ["section: none", f"why: {found['no_section']}"]
        return "\n".join(lines) + "\n"
    for name in SECTIONS:
        part = found["sections"].get(name) or {"present": False, "types": [], "purposes": []}
        lines.append(f"section: {name}")
        if not part["present"]:
            lines.append("none")
            continue
        lines.append(f"category: {LOCATION}")
        for kind in part["types"]:
            lines.append(f"type: {kind}")
        for purpose in part["purposes"]:
            lines.append(f"purpose: {purpose}")
    return "\n".join(lines) + "\n"


def parse_quote(text):
    """The answer in a quote file, read back. Pure: same text, same answer, no page needed."""
    found = {"sections": {}}
    section = None
    seen_section = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, value = line.partition(": ")
        if kind == "pkg":
            continue
        if kind == "not-a-data-safety-page":
            return None
        if kind == "section":
            seen_section = True
            if value == "none":
                return {"no_section": _why(text)}
            section = value
            if section in ("shared", "collected"):
                found["sections"][section] = {"present": False, "types": [], "purposes": []}
            continue
        if kind == "why":
            return {"no_section": value}
        if section not in ("shared", "collected"):
            continue
        part = found["sections"][section]
        if kind == "category":
            part["present"] = True
        elif kind == "type":
            part["types"].append(value)
        elif kind == "purpose":
            part["purposes"].append(value)
    if not seen_section:
        return None
    return found


def _why(text):
    for line in text.splitlines():
        if line.startswith("why: "):
            return line[5:].strip()
    return "the page has no data safety section"


# --- fetching, keeping and the phase -------------------------------------------------

def cache_path(pkg, suffix="html"):
    return os.path.join(paths.cache(pkg), f"datasafety.{suffix}")


def cache_meta_path(pkg):
    return os.path.join(paths.cache(pkg), "datasafety.json")


def cached(pkg, max_age_days=MAX_AGE_DAYS):
    """What an earlier run kept, when it is young enough to still describe the app."""
    meta_path = cache_meta_path(pkg)
    if not (os.path.exists(meta_path) and os.path.exists(cache_path(pkg, "txt"))):
        return None
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        then = time.mktime(time.strptime(meta["fetched_at"], "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, KeyError, OSError):
        return None
    if (time.time() - then) / 86400 > max_age_days:
        return None
    with open(cache_path(pkg, "txt"), encoding="utf-8") as f:
        return {"quote": f.read(), "meta": meta, "cached": True}


def fetch(pkg):
    """One page from Play, kept whole, and quoted down to the data safety part."""
    request = urllib.request.Request(URL.format(pkg=pkg), headers={"User-Agent": AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:
        markup = answer.read().decode("utf-8", "replace")
    meta = {"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": URL.format(pkg=pkg),
            "bytes": len(markup),
            "sha256": hashlib.sha256(markup.encode()).hexdigest(),
            "parser": PARSER}
    os.makedirs(paths.cache(pkg), exist_ok=True)
    with open(cache_path(pkg, "html"), "w", encoding="utf-8") as f:
        f.write(markup)
    return keep(pkg, markup, meta)


def keep(pkg, markup, meta=None):
    """Write the quote for a page already on disk, and the date it was read."""
    meta = meta or {"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "url": URL.format(pkg=pkg), "bytes": len(markup), "parser": PARSER}
    found = read_page(markup)
    quote = quote_of(pkg, {"meta": meta}, found)
    os.makedirs(paths.cache(pkg), exist_ok=True)
    with open(cache_path(pkg, "txt"), "w", encoding="utf-8") as f:
        f.write(quote)
    with open(cache_meta_path(pkg), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1)
        f.write(chr(10))
    return {"quote": quote, "meta": meta, "cached": False}


def page_for(pkg, refresh=False):
    """The quote for one app: from the kept copy when it is young, from Play otherwise."""
    if not refresh:
        kept = cached(pkg)
        if kept:
            return kept
    return fetch(pkg)


def quote_path(pkg):
    return cache_path(pkg, "txt")


def run(rid=None, apps=None, refresh=False, pause=PAUSE, progress=None, limit=None,
        max_doubt=0.05):
    """Read the Play page of the apps named in apps, and of no other app.

    Nothing is fetched unless an app is named: this step is on demand, because a page is a
    statement by a maker and the tool must not spend four minutes of the user's network to collect
    statements nobody asked for. Apps whose page was never asked for are written down as unknown
    with that reason, so a missing answer never reads as a clean one.
    """
    rid = store.resolve(rid)
    sheets = store.apps(rid)
    if not sheets:
        raise ValueError("no apps in this run; read the phone first: uv run locaudit capture")
    from_play = [sheet["pkg"] for sheet in sheets
                 if (sheet["facts"].get("install:from") or {}).get("value") == PLAY]
    wanted = [pkg for pkg in (apps or []) if pkg in from_play]
    todo = wanted[:limit] if limit else wanted

    counts = {"collected": 0, "shared": 0, "unknown": 0, "no_statement": 0, "not_play": 0}
    named = {"collected": [], "shared": []}
    unknown, doubt = {}, []
    fetched_at = None
    for index, pkg in enumerate(todo, 1):
        try:
            page = page_for(pkg, refresh=refresh)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
            unknown[pkg] = f"the Play page could not be fetched: {exc}"
            counts["unknown"] += 1
            if progress:
                progress(index, len(todo), pkg)
            continue
        if not page["cached"] and pause and index < len(todo):
            time.sleep(pause)
        found = parse_quote(page["quote"])
        fetched_at = page["meta"]["fetched_at"]
        if found is None or found.get("no_section"):
            doubt.append(pkg)

        def mutate(doc, found=found, page=page):
            written = set()

            def add(subject, value, **kw):
                written.add(subject)
                return store.add_fact(doc, subject, value, **kw)
            if found is None:
                # A page that no longer looks like a data safety page must not read as "collects
                # nothing": that is the failure scraping invites.
                add("unknown:datasafety", True, tier="T2", source="Play page", confidence="weak",
                    reason="the page did not look like a data safety page")
                return
            if found.get("no_section"):
                add("unknown:datasafety", True, tier="T2", source="Play page", confidence="weak",
                    reason=f"the page has no data safety section: {found['no_section']}")
                return
            add("datasafety:fetched", page["meta"]["fetched_at"], tier="T2", source="Play page",
                url=page["meta"]["url"], quote=PARSER)
            for kind in ("collected", "shared"):
                part = found["sections"].get(kind) or {"present": False, "types": [],
                                                       "purposes": []}
                add(f"datasafety:{kind}:location", "yes" if part["present"] else "no",
                    tier="T2", source="Play page",
                    typed=", ".join(part["types"]) or None)
            shared = found["sections"].get("shared") or {"present": False, "purposes": []}
            if shared["present"]:
                add("datasafety:purposes:location",
                    ", ".join(shared["purposes"]) or "no purpose stated",
                    tier="T2", source="Play page")
            for subject in OWNED:
                if subject not in written:
                    doc["facts"].pop(subject, None)

        sheet = store.update_app(pkg, mutate, rid)
        facts = sheet["facts"]
        if "unknown:datasafety" in facts:
            counts["no_statement"] += 1
            unknown[pkg] = (facts["unknown:datasafety"].get("reason")
                            or "the page did not say")
            continue
        for kind in ("collected", "shared"):
            if (facts.get(f"datasafety:{kind}:location") or {}).get("value") == "yes":
                counts[kind] += 1
                named[kind].append(pkg)

    for sheet in sheets:
        if sheet["pkg"] in from_play:
            continue
        counts["not_play"] += 1

        def mutate(doc):
            written = set()

            def add(subject, value, **kw):
                written.add(subject)
                return store.add_fact(doc, subject, value, **kw)
            add("unknown:datasafety", True, tier="T2", source="install info",
                reason="not installed from Google Play, which is where a data safety page lives")
            for subject in OWNED:
                if subject not in written:
                    doc["facts"].pop(subject, None)

        store.update_app(sheet["pkg"], mutate, rid)

    for pkg in from_play:
        if pkg in wanted:
            continue
        sheet = store.load_app(pkg, rid)
        if "datasafety:fetched" in sheet["facts"] or "unknown:datasafety" in sheet["facts"]:
            continue

        def mutate(doc):
            store.add_fact(doc, "unknown:datasafety", True, tier="T2", source="Play page",
                           confidence="weak",
                           reason="not read yet: the Play page is read on demand, for the apps "
                                  "asked for")
        store.update_app(pkg, mutate, rid)

    sheets = store.apps(rid)
    # What the run holds, not only what this pass asked for: a second pass with no app named must
    # not report zero pages read while the answers sit on disk.
    counts["collected"] = sum(1 for sheet in sheets
                              if (sheet["facts"].get("datasafety:collected:location") or {})
                              .get("value") == "yes")
    counts["shared"] = sum(1 for sheet in sheets
                           if (sheet["facts"].get("datasafety:shared:location") or {})
                           .get("value") == "yes")
    counts["no_statement"] = sum(1 for sheet in sheets
                                 if "unknown:datasafety" in sheet["facts"]
                                 and (sheet["facts"].get("install:from") or {})
                                 .get("value") == PLAY)
    missing = sorted(sheet["pkg"] for sheet in sheets
                     if sheet["pkg"] in from_play and "datasafety:fetched" not in sheet["facts"]
                     and "unknown:datasafety" not in sheet["facts"])
    # One page that stopped making sense is a finding about that app. Many of them, in one run, is
    # the page layout moving: that must fail the step rather than be written down 114 times.
    moved = len(doubt) > max(2, int(len(todo) * max_doubt)) if todo else False
    ok = not missing and not moved

    asked = len(todo)
    summary = (f"{len(from_play)} apps from Google Play: "
               f"{counts['collected']} say they collect location, "
               f"{counts['shared']} say they share it, "
               f"{counts['no_statement'] + counts['unknown']} have no statement the tool could read")
    if counts["not_play"]:
        many = "app" if counts["not_play"] == 1 else "apps"
        summary += (f"; {counts['not_play']} {many} did not come from Play, so there is no page "
                    f"to read")
    if moved:
        summary += (f"; {len(doubt)} of {len(todo)} pages did not look like a data safety page, so "
                    f"the page layout has probably moved and this step must be repaired before its "
                    f"numbers are used")
    if missing:
        summary += f"; {len(missing)} apps have no answer recorded: {', '.join(missing[:5])}"
    if fetched_at:
        summary += f"; read on {fetched_at[:10]}"
    if asked:
        summary += (f"; {asked} page{'s' if asked != 1 else ''} asked for in this pass")
    else:
        summary += "; no page was asked for in this pass, so nothing was fetched"
    store.require(rid, "datasafety", ok, summary)
    return {"run": rid, "ok": ok, "summary": summary, "counts": counts, "apps_in": named,
            "unknown": unknown, "fetched_at": fetched_at, "missing": missing,
            "layout_doubt": doubt, "layout_moved": moved, "from_play": len(from_play)}

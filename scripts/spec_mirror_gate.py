#!/usr/bin/env python3
"""spec-mirror-gate: compare a MIRRORED openapi.json against busbar core's, STRUCTURALLY.

busbar core generates crates/busbar/src/admin/v1/json/openapi.json and that document is the
source of truth. Other repos keep tracked copies of it (busbar-admin's ./openapi.json, the
marketing site's website/public/openapi.json). Those copies are the thing this gate guards.

WHY THIS EXISTS. The pre-existing drift check compared `info.version` STRINGS. That check was
green on a mirror whose HookView was missing `phase`, `fires_at` and `groups`, because the stale
copy carried the same version string as core's current one. A gate that reports green about a
property it never looks at is worse than no gate: it converts an unknown into a false assurance.
So this gate never looks at the version. It walks components.schemas schema-by-schema and
property-by-property, and paths path-by-path and method-by-method, and every finding NAMES the
schema and the property (or the path and the method). "The specs differ" is not a finding.

FAIL CLOSED. If core's spec cannot be fetched or cannot be parsed, that is exit code 2, a
FAILURE. Unknown is not green. There is no --skip-on-network-error and there must never be one.

Exit codes:
  0  mirror matches core structurally
  1  structural drift found (each finding is printed, named)
  2  FATAL: core's spec could not be fetched or parsed, or the mirror could not be read

Usage:
  spec_mirror_gate.py --mirror openapi.json --busbar-ref dev
  spec_mirror_gate.py --mirror website/public/openapi.json --core-spec /tmp/core.json
  spec_mirror_gate.py --selftest
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

CORE_REPO = "GetBusbar/busbar"
CORE_SPEC_PATH = "crates/busbar/src/admin/v1/json/openapi.json"
DEFAULT_REF = "dev"

# The keys type_sig() folds into one signature. A type-changed finding accounts for all of them,
# so the residual sweep must not report them again.
TYPE_KEYS = (
    "type",
    "format",
    "nullable",
    "$ref",
    "oneOf",
    "anyOf",
    "allOf",
    "items",
    "additionalProperties",
)

HTTP_METHODS = (
    "get",
    "put",
    "post",
    "delete",
    "patch",
    "head",
    "options",
    "trace",
)


class Fatal(Exception):
    """Core's spec could not be obtained or understood. Never downgrade this to a skip."""


# ---------------------------------------------------------------------------
# fetching core's spec
# ---------------------------------------------------------------------------


def _get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


LATEST_RELEASE = "latest-release"


def resolve_ref(ref, timeout=30, opener=None):
    """Turn the sentinel `latest-release` into a real tag, or pass a ref through unchanged.

    A repo that PUBLISHES a spec (the marketing site) or ships a client for the RELEASED engine
    (busbar-admin) must track the released document, not whatever is on a branch. Resolving that
    tag is itself a fetch, so it gets the same rule as every other fetch here: it cannot fail
    quietly. A ref we could not resolve is FATAL.
    """
    if ref != LATEST_RELEASE:
        return ref
    get = opener or _get
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "spec-mirror-gate"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    url = "https://api.github.com/repos/%s/releases/latest" % CORE_REPO
    try:
        payload = json.loads(get(url, headers, timeout))
    except Exception as exc:  # noqa: BLE001
        raise Fatal(
            "could not resolve %r: %s failed: %s.\n"
            "The pre-existing spec-drift job treated exactly this as a warning and exited 0. "
            "That is the fail-open this gate exists to remove." % (ref, url, exc)
        )
    tag = payload.get("tag_name")
    if not tag:
        raise Fatal(
            "could not resolve %r: %s returned no tag_name (rate limited?)" % (ref, url)
        )
    return tag


def fetch_core_spec(ref, timeout=30, opener=None):
    """Return core's openapi.json bytes at `ref`, or raise Fatal.

    Tries the GitHub contents API first when a token is present (works for private repos),
    then raw.githubusercontent.com. Both failing is FATAL, not a skip.
    """
    get = opener or _get
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    attempts = []
    if token:
        attempts.append(
            (
                "https://api.github.com/repos/%s/contents/%s?ref=%s"
                % (CORE_REPO, CORE_SPEC_PATH, ref),
                {
                    "Authorization": "Bearer %s" % token,
                    "Accept": "application/vnd.github.raw",
                    "User-Agent": "spec-mirror-gate",
                },
            )
        )
    attempts.append(
        (
            "https://raw.githubusercontent.com/%s/%s/%s"
            % (CORE_REPO, ref, CORE_SPEC_PATH),
            {"User-Agent": "spec-mirror-gate"},
        )
    )

    errors = []
    for url, headers in attempts:
        try:
            return get(url, headers, timeout)
        except Exception as exc:  # noqa: BLE001 - every failure mode is fatal here
            errors.append("%s: %s" % (url, exc))
    raise Fatal(
        "could not fetch core's %s at ref %r from %s:\n  %s"
        % (CORE_SPEC_PATH, ref, CORE_REPO, "\n  ".join(errors))
    )


def load_spec(raw, origin):
    try:
        doc = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        raise Fatal("%s is not parseable JSON: %s" % (origin, exc))
    if not isinstance(doc, dict):
        raise Fatal("%s is not a JSON object" % origin)
    if not isinstance(doc.get("components"), dict) or not isinstance(
        doc["components"].get("schemas"), dict
    ):
        raise Fatal("%s has no components.schemas object" % origin)
    if not isinstance(doc.get("paths"), dict):
        raise Fatal("%s has no paths object" % origin)
    return doc


# ---------------------------------------------------------------------------
# structural model
# ---------------------------------------------------------------------------


def type_sig(node):
    """A compact, order-insensitive description of a schema node's TYPE."""
    if node is True:
        return "any"
    if node is False:
        return "never"
    if not isinstance(node, dict):
        return "literal(%r)" % (node,)
    parts = []
    if "$ref" in node:
        parts.append("$ref=%s" % node["$ref"])
    t = node.get("type")
    if t is not None:
        parts.append(
            "type=%s" % (",".join(sorted(str(x) for x in t)) if isinstance(t, list) else t)
        )
    if "format" in node:
        parts.append("format=%s" % node["format"])
    if node.get("nullable") is True:
        parts.append("nullable=true")
    for kw in ("oneOf", "anyOf", "allOf"):
        sub = node.get(kw)
        if isinstance(sub, list):
            parts.append("%s=[%s]" % (kw, ",".join(sorted(type_sig(s) for s in sub))))
    items = node.get("items")
    if isinstance(items, (dict, bool)):
        parts.append("items(%s)" % type_sig(items))
    ap = node.get("additionalProperties")
    if isinstance(ap, dict):
        parts.append("additionalProperties(%s)" % type_sig(ap))
    elif ap is False:
        parts.append("additionalProperties=false")
    return " ".join(parts) if parts else "any"


def enum_of(node):
    if isinstance(node, dict) and isinstance(node.get("enum"), list):
        return [json.dumps(v, sort_keys=True) for v in node["enum"]]
    return None


def props_of(node):
    if isinstance(node, dict) and isinstance(node.get("properties"), dict):
        return node["properties"]
    return {}


def required_of(node):
    if isinstance(node, dict) and isinstance(node.get("required"), list):
        return set(str(x) for x in node["required"])
    return set()


def esc(token):
    """JSON Pointer escaping (RFC 6901)."""
    return str(token).replace("~", "~0").replace("/", "~1")


def collect_nodes(node, prefix, pointer, out):
    """Flatten a schema into {dotted-path: (node, json-pointer)}.

    Two names for the same place: the dotted path (HookView.groups[]) is what a human reads in a
    finding, the JSON pointer is what the residual sweep uses to suppress double-reporting.
    """
    out[prefix] = (node, pointer)
    if not isinstance(node, dict):
        return
    for name, sub in sorted(props_of(node).items()):
        collect_nodes(sub, "%s.%s" % (prefix, name),
                      "%s/properties/%s" % (pointer, esc(name)), out)
    items = node.get("items")
    if isinstance(items, dict):
        collect_nodes(items, "%s[]" % prefix, "%s/items" % pointer, out)
    ap = node.get("additionalProperties")
    if isinstance(ap, dict):
        collect_nodes(ap, "%s{}" % prefix, "%s/additionalProperties" % pointer, out)


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------


class Finding(object):
    def __init__(self, kind, subject, detail, covers=None):
        self.kind = kind
        self.subject = subject
        self.detail = detail
        # JSON pointer subtree this finding already accounts for, so the residual sweep does not
        # report the same divergence a second time in a less readable form.
        if covers is None:
            self.covers = []
        elif isinstance(covers, str):
            self.covers = [covers]
        else:
            self.covers = list(covers)

    def __str__(self):
        return "%-22s %-46s %s" % (self.kind, self.subject, self.detail)


def _sorted_diff(a, b):
    return sorted(a - b), sorted(b - a)


def compare_schemas(core, mirror, findings):
    core_s = core["components"]["schemas"]
    mirror_s = mirror["components"]["schemas"]

    missing, extra = _sorted_diff(set(core_s), set(mirror_s))
    for name in missing:
        findings.append(
            Finding(
                "schema-missing",
                name,
                "core defines schema %r; the mirror does not have it at all" % name,
                covers="/components/schemas/%s" % esc(name),
            )
        )
    for name in extra:
        findings.append(
            Finding(
                "schema-extra",
                name,
                "the mirror defines schema %r; core does not" % name,
                covers="/components/schemas/%s" % esc(name),
            )
        )

    for name in sorted(set(core_s) & set(mirror_s)):
        core_nodes = {}
        mirror_nodes = {}
        root = "/components/schemas/%s" % esc(name)
        collect_nodes(core_s[name], name, root, core_nodes)
        collect_nodes(mirror_s[name], name, root, mirror_nodes)

        for path in sorted(set(core_nodes) & set(mirror_nodes)):
            cn, ptr = core_nodes[path]
            mn = mirror_nodes[path][0]

            # properties
            cp, mp = set(props_of(cn)), set(props_of(mn))
            gone, added = _sorted_diff(cp, mp)
            for p in gone:
                findings.append(
                    Finding(
                        "property-missing",
                        "%s.%s" % (path, p),
                        "schema %s is missing property %r that core has (core type: %s)"
                        % (path, p, type_sig(props_of(cn)[p])),
                        covers="%s/properties/%s" % (ptr, esc(p)),
                    )
                )
            for p in added:
                findings.append(
                    Finding(
                        "property-extra",
                        "%s.%s" % (path, p),
                        "schema %s has property %r that core does not (mirror type: %s)"
                        % (path, p, type_sig(props_of(mn)[p])),
                        covers="%s/properties/%s" % (ptr, esc(p)),
                    )
                )

            # required
            cr, mr = required_of(cn), required_of(mn)
            gone, added = _sorted_diff(cr, mr)
            for p in gone:
                findings.append(
                    Finding(
                        "required-missing",
                        "%s.%s" % (path, p),
                        "core marks %r required on schema %s; the mirror does not"
                        % (p, path),
                        covers="%s/required" % ptr,
                    )
                )
            for p in added:
                findings.append(
                    Finding(
                        "required-extra",
                        "%s.%s" % (path, p),
                        "the mirror marks %r required on schema %s; core does not"
                        % (p, path),
                        covers="%s/required" % ptr,
                    )
                )

            # enum
            ce, me = enum_of(cn), enum_of(mn)
            if ce is None and me is not None:
                findings.append(
                    Finding(
                        "enum-added",
                        path,
                        "the mirror constrains %s to an enum (%s); core does not"
                        % (path, ", ".join(me)),
                        covers="%s/enum" % ptr,
                    )
                )
            elif ce is not None and me is None:
                findings.append(
                    Finding(
                        "enum-dropped",
                        path,
                        "core constrains %s to an enum (%s); the mirror does not"
                        % (path, ", ".join(ce)),
                        covers="%s/enum" % ptr,
                    )
                )
            elif ce is not None and me is not None:
                gone, added = _sorted_diff(set(ce), set(me))
                for v in gone:
                    findings.append(
                        Finding(
                            "enum-variant-missing",
                            path,
                            "enum %s is missing variant %s that core has" % (path, v),
                            covers="%s/enum" % ptr,
                        )
                    )
                for v in added:
                    findings.append(
                        Finding(
                            "enum-variant-extra",
                            path,
                            "enum %s has variant %s that core does not" % (path, v),
                            covers="%s/enum" % ptr,
                        )
                    )

            # type
            cts, mts = type_sig(cn), type_sig(mn)
            if cts != mts:
                findings.append(
                    Finding(
                        "type-changed",
                        path,
                        "%s is %s in core but %s in the mirror" % (path, cts, mts),
                        covers=["%s/%s" % (ptr, k) for k in TYPE_KEYS],
                    )
                )


def _op_params(op):
    out = {}
    if isinstance(op, dict) and isinstance(op.get("parameters"), list):
        for p in op["parameters"]:
            if isinstance(p, dict) and "name" in p:
                out["%s:%s" % (p.get("in", "?"), p["name"])] = bool(p.get("required"))
    return out


def _op_body_sig(op):
    if not isinstance(op, dict):
        return None
    body = op.get("requestBody")
    if not isinstance(body, dict):
        return None
    content = body.get("content")
    if not isinstance(content, dict):
        return "requestBody(required=%s)" % bool(body.get("required"))
    media = sorted(content)
    sigs = [
        "%s=%s" % (m, type_sig((content[m] or {}).get("schema", {}))) for m in media
    ]
    return "requestBody(required=%s, %s)" % (bool(body.get("required")), "; ".join(sigs))


def _op_responses(op):
    out = {}
    if isinstance(op, dict) and isinstance(op.get("responses"), dict):
        for code, resp in op["responses"].items():
            content = (resp or {}).get("content")
            if isinstance(content, dict):
                out[str(code)] = "; ".join(
                    "%s=%s" % (m, type_sig((content[m] or {}).get("schema", {})))
                    for m in sorted(content)
                )
            else:
                out[str(code)] = "no-content"
    return out


def compare_paths(core, mirror, findings):
    cp, mp = core["paths"], mirror["paths"]
    missing, extra = _sorted_diff(set(cp), set(mp))
    for p in missing:
        findings.append(
            Finding(
                "path-missing",
                p,
                "core serves path %s; the mirror does not document it" % p,
                covers="/paths/%s" % esc(p),
            )
        )
    for p in extra:
        findings.append(
            Finding(
                "path-extra",
                p,
                "the mirror documents path %s; core does not serve it" % p,
                covers="/paths/%s" % esc(p),
            )
        )

    for p in sorted(set(cp) & set(mp)):
        c_ops = {m: cp[p][m] for m in HTTP_METHODS if isinstance(cp[p], dict) and m in cp[p]}
        m_ops = {m: mp[p][m] for m in HTTP_METHODS if isinstance(mp[p], dict) and m in mp[p]}
        gone, added = _sorted_diff(set(c_ops), set(m_ops))
        for m in gone:
            findings.append(
                Finding(
                    "method-missing",
                    "%s %s" % (m.upper(), p),
                    "core serves %s %s; the mirror does not document it" % (m.upper(), p),
                    covers="/paths/%s/%s" % (esc(p), m),
                )
            )
        for m in added:
            findings.append(
                Finding(
                    "method-extra",
                    "%s %s" % (m.upper(), p),
                    "the mirror documents %s %s; core does not serve it" % (m.upper(), p),
                    covers="/paths/%s/%s" % (esc(p), m),
                )
            )

        for m in sorted(set(c_ops) & set(m_ops)):
            subject = "%s %s" % (m.upper(), p)
            optr = "/paths/%s/%s" % (esc(p), m)
            c_par, m_par = _op_params(c_ops[m]), _op_params(m_ops[m])
            g, a = _sorted_diff(set(c_par), set(m_par))
            for name in g:
                findings.append(
                    Finding(
                        "param-missing",
                        "%s %s" % (subject, name),
                        "core takes parameter %s on %s; the mirror does not" % (name, subject),
                        covers="%s/parameters" % optr,
                    )
                )
            for name in a:
                findings.append(
                    Finding(
                        "param-extra",
                        "%s %s" % (subject, name),
                        "the mirror takes parameter %s on %s; core does not"
                        % (name, subject),
                        covers="%s/parameters" % optr,
                    )
                )
            for name in sorted(set(c_par) & set(m_par)):
                if c_par[name] != m_par[name]:
                    findings.append(
                        Finding(
                            "param-required-changed",
                            "%s %s" % (subject, name),
                            "parameter %s on %s is required=%s in core but required=%s in the mirror"
                            % (name, subject, c_par[name], m_par[name]),
                            covers="%s/parameters" % optr,
                        )
                    )

            cb, mb = _op_body_sig(c_ops[m]), _op_body_sig(m_ops[m])
            if cb != mb:
                findings.append(
                    Finding(
                        "request-body-changed",
                        subject,
                        "%s request body is %s in core but %s in the mirror"
                        % (subject, cb, mb),
                        covers="%s/requestBody" % optr,
                    )
                )

            c_res, m_res = _op_responses(c_ops[m]), _op_responses(m_ops[m])
            g, a = _sorted_diff(set(c_res), set(m_res))
            for code in g:
                findings.append(
                    Finding(
                        "response-missing",
                        "%s %s" % (subject, code),
                        "core documents response %s on %s; the mirror does not"
                        % (code, subject),
                        covers="%s/responses/%s" % (optr, esc(code)),
                    )
                )
            for code in a:
                findings.append(
                    Finding(
                        "response-extra",
                        "%s %s" % (subject, code),
                        "the mirror documents response %s on %s; core does not"
                        % (code, subject),
                        covers="%s/responses/%s" % (optr, esc(code)),
                    )
                )
            for code in sorted(set(c_res) & set(m_res)):
                if c_res[code] != m_res[code]:
                    findings.append(
                        Finding(
                            "response-changed",
                            "%s %s" % (subject, code),
                            "response %s on %s is %s in core but %s in the mirror"
                            % (code, subject, c_res[code], m_res[code]),
                            covers="%s/responses/%s" % (optr, esc(code)),
                        )
                    )


# ---------------------------------------------------------------------------
# residual sweep
# ---------------------------------------------------------------------------
#
# The structural walk above names the differences an API consumer can BREAK on. It is not, and
# should not be, a byte comparison. But a mirror is a COPY of a generated file, so anything the
# structural walk did not look at is still a difference someone has to know about, and staying
# green on it would reintroduce the exact defect this gate exists to kill: reporting green about
# something it never checked. So after the named walk, sweep the whole document and report every
# remaining divergence by JSON pointer, minus what the walk already accounted for.
#
# In practice this is what catches a stale `info.version` and a `description` that core rewrote,
# neither of which changes a wire shape but both of which mean the copy is not the original.


def pointer_diffs(core, mirror, prefix="", out=None):
    """Every JSON pointer at which the two documents disagree."""
    if out is None:
        out = []
    if isinstance(core, dict) and isinstance(mirror, dict):
        for k in sorted(set(core) | set(mirror)):
            ptr = "%s/%s" % (prefix, esc(k))
            if k not in mirror:
                out.append((ptr, "present in core, absent from the mirror"))
            elif k not in core:
                out.append((ptr, "present in the mirror, absent from core"))
            else:
                pointer_diffs(core[k], mirror[k], ptr, out)
    elif isinstance(core, list) and isinstance(mirror, list):
        if len(core) != len(mirror):
            out.append((prefix, "%d entries in core, %d in the mirror"
                        % (len(core), len(mirror))))
        else:
            for i, (a, b) in enumerate(zip(core, mirror)):
                pointer_diffs(a, b, "%s/%d" % (prefix, i), out)
    elif core != mirror:
        out.append((prefix, describe_scalar_diff(core, mirror)))
    return out


def describe_scalar_diff(core, mirror):
    """Say WHERE two scalars differ. Two long descriptions that share a prefix must not both
    truncate to the same 120 characters and read as if the tool is reporting nothing."""
    if isinstance(core, str) and isinstance(mirror, str) and (
        len(core) > 100 or len(mirror) > 100
    ):
        i = 0
        while i < min(len(core), len(mirror)) and core[i] == mirror[i]:
            i += 1
        return (
            "text differs at character %d (core is %d chars, the mirror is %d); "
            "from there core has %s and the mirror has %s"
            % (i, len(core), len(mirror),
               json.dumps(core[i:i + 90]), json.dumps(mirror[i:i + 90]))
        )
    return "core has %s, the mirror has %s" % (
        json.dumps(core)[:160],
        json.dumps(mirror)[:160],
    )


DOC_TEXT_KEYS = ("description", "summary", "title", "example", "examples", "externalDocs")


def compare_residual(core, mirror, findings):
    covered = []
    for f in findings:
        covered.extend(f.covers)
    for ptr, detail in pointer_diffs(core, mirror):
        if any(ptr == c or ptr.startswith(c + "/") for c in covered):
            continue
        last = ptr.rsplit("/", 1)[-1] if "/" in ptr else ptr
        if last in DOC_TEXT_KEYS:
            kind = "doc-text-changed"
        elif ptr == "/info/version":
            kind = "version-changed"
        else:
            kind = "unclassified-difference"
        findings.append(Finding(kind, ptr, "%s: %s" % (ptr, detail)))


def compare(core, mirror):
    findings = []
    compare_schemas(core, mirror, findings)
    compare_paths(core, mirror, findings)
    compare_residual(core, mirror, findings)
    return findings


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def report(findings, mirror_label, core_label, stream=sys.stdout):
    stream.write("spec-mirror-gate\n")
    stream.write("  mirror: %s\n" % mirror_label)
    stream.write("  core:   %s\n" % core_label)
    stream.write("  comparison: STRUCTURAL, schema-by-schema and property-by-property over\n"
                 "              components.schemas, and path-by-path and method-by-method over\n"
                 "              paths. The verdict never rests on info.version: a stale mirror\n"
                 "              carrying core's own version string is exactly the false green\n"
                 "              this gate replaces.\n\n")
    if not findings:
        stream.write("GREEN: the mirror is identical to core's spec.\n")
        return 0
    by_kind = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)
    stream.write("RED: %d difference(s) between the mirror and core.\n\n" % len(findings))
    for kind in sorted(by_kind):
        stream.write("[%s] %d\n" % (kind, len(by_kind[kind])))
        for f in by_kind[kind]:
            stream.write("  - %s\n" % f.detail)
        stream.write("\n")
    stream.write(
        "The mirror is a COPY of a generated document. Fix it by regenerating in core\n"
        "  (UPDATE_OPENAPI=1 cargo test -p busbar --features openapi-schema --locked \\\n"
        "     openapi_json_matches_committed_file)\n"
        "and copying %s into this repo. Do not hand-edit the mirror,\n"
        "and do not relax this gate.\n" % CORE_SPEC_PATH
    )
    return 1


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(
        prog="spec_mirror_gate.py",
        description="Compare a mirrored openapi.json against busbar core's, structurally.",
    )
    p.add_argument("--mirror", help="path to this repo's mirrored openapi.json")
    p.add_argument(
        "--busbar-ref",
        default=DEFAULT_REF,
        help="the busbar core git ref to compare against: a branch, a tag, a sha, or the "
        "sentinel %r which resolves to the latest busbar release tag (default: %s, the engine "
        "that ships next)" % (LATEST_RELEASE, DEFAULT_REF),
    )
    p.add_argument(
        "--core-spec",
        help="compare against a LOCAL core spec file instead of fetching it (offline use)",
    )
    p.add_argument(
        "--selftest",
        action="store_true",
        help="prove this gate goes RED on every finding class it claims to detect",
    )
    p.add_argument("--timeout", type=int, default=30, help="fetch timeout in seconds")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.selftest:
        import spec_mirror_selftest

        return spec_mirror_selftest.run(sys.stdout)

    if not args.mirror:
        sys.stderr.write("FATAL: --mirror is required (or use --selftest)\n")
        return 2

    try:
        try:
            with open(args.mirror, "rb") as fh:
                mirror_raw = fh.read()
        except OSError as exc:
            raise Fatal("could not read the mirror at %s: %s" % (args.mirror, exc))
        mirror = load_spec(mirror_raw, "the mirror at %s" % args.mirror)

        if args.core_spec:
            try:
                with open(args.core_spec, "rb") as fh:
                    core_raw = fh.read()
            except OSError as exc:
                raise Fatal("could not read --core-spec %s: %s" % (args.core_spec, exc))
            core_label = "%s (local file)" % args.core_spec
        else:
            ref = resolve_ref(args.busbar_ref, timeout=args.timeout)
            core_raw = fetch_core_spec(ref, timeout=args.timeout)
            core_label = "%s@%s:%s%s" % (
                CORE_REPO,
                ref,
                CORE_SPEC_PATH,
                " (resolved from %s)" % LATEST_RELEASE
                if ref != args.busbar_ref
                else "",
            )
        core = load_spec(core_raw, "core's spec (%s)" % core_label)
    except Fatal as exc:
        sys.stderr.write(
            "FATAL: %s\n"
            "This gate FAILS CLOSED. An unknown is not a pass: it is exactly the state the\n"
            "old version-string check treated as green while the shapes had diverged.\n" % exc
        )
        return 2

    return report(compare(core, mirror), args.mirror, core_label)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())

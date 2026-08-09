#!/usr/bin/env python3
"""Self-test for spec_mirror_gate: prove the gate goes RED on every class it claims to detect.

Run it via the gate itself: `python3 spec_mirror_gate.py --selftest`.

The point of this file is the ORDER the workflows use it in: self-test FIRST, then trust the
gate's verdict. A gate nobody has proved can fail is indistinguishable from `exit 0`, and that
is precisely how the version-string drift check stayed green over a mirror whose HookView had
lost `phase`, `fires_at` and `groups`.

Every case below asserts three things, not one:
  1. the gate returns a NON-ZERO verdict on the broken pair,
  2. at least one finding is of the EXPECTED KIND, and
  3. that finding NAMES the schema/property (or path/method) at fault.
Point 3 is the one that matters. "The specs differ" would satisfy 1 and 2 and still be useless.

The last case is the fail-closed case: core's spec unreachable must be FATAL (exit 2), never a
skip and never a pass.
"""

import io
import json
import os
import tempfile

import spec_mirror_gate as gate


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def base_spec():
    """A tiny but structurally realistic spec, shaped like the real admin document."""
    return {
        "openapi": "3.0.3",
        "info": {"title": "selftest", "version": "9.9.9"},
        "paths": {
            "/hooks": {
                "get": {
                    "operationId": "list_hooks",
                    "parameters": [
                        {"name": "limit", "in": "query", "required": False,
                         "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/HookView"},
                                    }
                                }
                            }
                        }
                    },
                },
                "post": {
                    "operationId": "create_hook",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HookView"}
                            }
                        },
                    },
                    "responses": {"201": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/HookView"}}}}},
                },
            }
        },
        "components": {
            "schemas": {
                "HookView": {
                    "type": "object",
                    "required": ["name", "kind"],
                    "properties": {
                        "name": {"type": "string"},
                        "kind": {"type": "string"},
                        "phase": {"$ref": "#/components/schemas/HookPhase"},
                        "fires_at": {"type": "string", "format": "date-time",
                                     "nullable": True},
                        "groups": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "HookPhase": {
                    "type": "string",
                    "enum": ["pre", "post", "error"],
                },
                "SecretView": {
                    "type": "object",
                    "properties": {"alias": {"type": "string"}},
                },
            }
        },
    }


def clone(spec):
    return json.loads(json.dumps(spec))


# Each case: (label, mutate_mirror, expected_kind, must_name)
def cases():
    def drop_schema(m):
        del m["components"]["schemas"]["SecretView"]

    def add_schema(m):
        m["components"]["schemas"]["GhostView"] = {"type": "object", "properties": {}}

    def drop_props(m):
        # The real defect, in miniature: the mirror's HookView is three properties behind core.
        for p in ("phase", "fires_at", "groups"):
            del m["components"]["schemas"]["HookView"]["properties"][p]

    def add_prop(m):
        m["components"]["schemas"]["HookView"]["properties"]["legacy_stage"] = {
            "type": "string"
        }

    def change_required(m):
        m["components"]["schemas"]["HookView"]["required"] = ["name"]

    def change_enum(m):
        m["components"]["schemas"]["HookPhase"]["enum"] = ["pre", "post"]

    def change_type(m):
        m["components"]["schemas"]["HookView"]["properties"]["groups"] = {"type": "string"}

    def drop_path(m):
        del m["paths"]["/hooks"]

    def drop_method(m):
        del m["paths"]["/hooks"]["post"]

    def drop_param(m):
        m["paths"]["/hooks"]["get"]["parameters"] = []

    def change_description(m):
        m["components"]["schemas"]["HookView"]["properties"]["phase"]["description"] = (
            "an older sentence core no longer ships"
        )

    def change_version(m):
        m["info"]["version"] = "9.9.8"

    def change_unclassified(m):
        m["paths"]["/hooks"]["get"]["operationId"] = "listHooks"

    def change_response(m):
        m["paths"]["/hooks"]["get"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ] = {"type": "object"}

    return [
        ("schema missing from the mirror", drop_schema, "schema-missing", "SecretView"),
        ("schema the mirror has and core does not", add_schema, "schema-extra", "GhostView"),
        ("properties missing from a schema", drop_props, "property-missing", "HookView"),
        ("property the mirror has and core does not", add_prop, "property-extra",
         "legacy_stage"),
        ("required set changed", change_required, "required-missing", "kind"),
        ("enum variant dropped", change_enum, "enum-variant-missing", "HookPhase"),
        ("property type changed", change_type, "type-changed", "HookView.groups"),
        ("path missing from the mirror", drop_path, "path-missing", "/hooks"),
        ("method missing from the mirror", drop_method, "method-missing", "POST /hooks"),
        ("parameter missing from an operation", drop_param, "param-missing", "limit"),
        ("response schema changed", change_response, "response-changed", "GET /hooks"),
        # The residual sweep. These change no wire shape, but a mirror is a COPY, so the gate
        # must still name them rather than stay green on a document it did not fully compare.
        ("description text drifted", change_description, "doc-text-changed",
         "/components/schemas/HookView/properties/phase/description"),
        ("info.version drifted", change_version, "version-changed", "/info/version"),
        ("difference outside the structural walk", change_unclassified,
         "unclassified-difference", "/paths/~1hooks/get/operationId"),
    ]


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


def run(out):
    failures = []
    passed = 0

    out.write("spec-mirror-gate self-test: prove RED before trusting GREEN\n")
    out.write("=" * 72 + "\n\n")

    # 0. The identical pair must be GREEN. A gate that fails on everything is also useless.
    core = base_spec()
    findings = gate.compare(core, clone(core))
    if findings:
        failures.append(
            "control: an identical mirror produced %d finding(s), expected none: %s"
            % (len(findings), "; ".join(str(f) for f in findings[:5]))
        )
        out.write("  FAIL  control (identical mirror must be GREEN)\n")
    else:
        passed += 1
        out.write("  ok    control (identical mirror is GREEN)\n")

    # 1..n. Every finding class must go RED and must NAME the thing.
    for label, mutate, kind, must_name in cases():
        mirror = clone(core)
        mutate(mirror)
        findings = gate.compare(core, mirror)
        kinds = set(f.kind for f in findings)
        named = [f for f in findings if f.kind == kind and must_name in f.detail]
        if not findings:
            failures.append("%s: gate stayed GREEN on a broken mirror" % label)
            out.write("  FAIL  %-46s stayed GREEN\n" % label)
        elif kind not in kinds:
            failures.append(
                "%s: expected a %r finding, got kinds %s" % (label, kind, sorted(kinds))
            )
            out.write("  FAIL  %-46s wrong kind %s\n" % (label, sorted(kinds)))
        elif not named:
            failures.append(
                "%s: a %r finding was raised but it does not NAME %r"
                % (label, kind, must_name)
            )
            out.write("  FAIL  %-46s does not name %s\n" % (label, must_name))
        else:
            passed += 1
            out.write("  ok    %-46s RED, names %s\n" % (label, must_name))

    # Fail-closed 1: core's spec cannot be fetched.
    with tempfile.TemporaryDirectory() as tmp:
        mirror_path = os.path.join(tmp, "openapi.json")
        with open(mirror_path, "w") as fh:
            json.dump(core, fh)

        def exploding_opener(url, headers, timeout):
            raise IOError("selftest: network is down")

        real = gate.fetch_core_spec
        try:
            gate.fetch_core_spec = lambda ref, timeout=30, opener=None: real(
                ref, timeout=timeout, opener=exploding_opener
            )
            rc = gate.main(["--mirror", mirror_path, "--busbar-ref", "dev"])
        finally:
            gate.fetch_core_spec = real
        if rc == 2:
            passed += 1
            out.write("  ok    %-46s FATAL (exit 2), not a skip\n" % "core spec unfetchable")
        else:
            failures.append(
                "unfetchable core spec returned %r; it must be FATAL (2), never a skip" % rc
            )
            out.write("  FAIL  %-46s returned %r, expected 2\n"
                      % ("core spec unfetchable", rc))

        # Fail-closed 1b: `latest-release` cannot be resolved to a tag. Resolving the tag is a
        # second network call, so it is a second chance to fail open. It must not take it. The
        # pre-existing spec-drift job resolved this exact tag and printed a ::warning:: + exit 0
        # when the API was rate-limited, which is how a rate-limited runner reported "no drift".
        real_resolve = gate.resolve_ref
        try:
            gate.resolve_ref = lambda ref, timeout=30, opener=None: real_resolve(
                ref, timeout=timeout, opener=exploding_opener
            )
            rc = gate.main(["--mirror", mirror_path, "--busbar-ref", gate.LATEST_RELEASE])
        finally:
            gate.resolve_ref = real_resolve
        if rc == 2:
            passed += 1
            out.write("  ok    %-46s FATAL (exit 2), not a skip\n"
                      % "latest-release unresolvable")
        else:
            failures.append(
                "an unresolvable %r returned %r; it must be FATAL (2), never a skip"
                % (gate.LATEST_RELEASE, rc)
            )
            out.write("  FAIL  %-46s returned %r, expected 2\n"
                      % ("latest-release unresolvable", rc))

        # Fail-closed 2: core's spec is fetched but is not parseable.
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w") as fh:
            fh.write("{ this is not json")
        rc = gate.main(["--mirror", mirror_path, "--core-spec", bad])
        if rc == 2:
            passed += 1
            out.write("  ok    %-46s FATAL (exit 2), not a skip\n" % "core spec unparseable")
        else:
            failures.append("unparseable core spec returned %r; it must be FATAL (2)" % rc)
            out.write("  FAIL  %-46s returned %r, expected 2\n"
                      % ("core spec unparseable", rc))

        # Fail-closed 3: the version string alone must NOT be able to make it green. This is the
        # exact false-green that shipped: same info.version, different shapes.
        same_version_stale = clone(core)
        for p in ("phase", "fires_at", "groups"):
            del same_version_stale["components"]["schemas"]["HookView"]["properties"][p]
        assert same_version_stale["info"]["version"] == core["info"]["version"]
        stale_path = os.path.join(tmp, "stale.json")
        with open(stale_path, "w") as fh:
            json.dump(same_version_stale, fh)
        core_path = os.path.join(tmp, "core.json")
        with open(core_path, "w") as fh:
            json.dump(core, fh)
        buf = io.StringIO()
        rc = gate.report(
            gate.compare(core, same_version_stale), stale_path, core_path, buf
        )
        text = buf.getvalue()
        if rc == 1 and all(n in text for n in ("HookView", "phase", "fires_at", "groups")):
            passed += 1
            out.write("  ok    %-46s RED despite an identical info.version\n"
                      % "stale mirror, same version string")
        else:
            failures.append(
                "a stale mirror carrying core's own info.version returned %r; it must be RED "
                "and must name HookView/phase/fires_at/groups" % rc
            )
            out.write("  FAIL  %-46s rc=%r\n" % ("stale mirror, same version string", rc))

    out.write("\n" + "=" * 72 + "\n")
    if failures:
        out.write("SELF-TEST FAILED: %d of %d checks did not hold.\n"
                  % (len(failures), passed + len(failures)))
        for f in failures:
            out.write("  - %s\n" % f)
        out.write("\nDo NOT trust this gate's verdict until the self-test is green.\n")
        return 1
    out.write("SELF-TEST PASSED: %d checks. Every finding class goes RED on a broken\n"
              "mirror and names the schema/property at fault, and an unknown core spec is\n"
              "FATAL rather than green. The gate's verdict can be trusted.\n" % passed)
    return 0

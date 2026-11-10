#!/usr/bin/env python3
"""Validation helpers for the W0 state-services documentation contract.

Standard library only. These checks validate checked-in documents, source
symbols and configuration examples; they never run Cargo, the Rootyard binary
or an external PostgreSQL/Blob service.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "docs" / "design" / "state-services"
MISSING = object()
REQUIRED_CATEGORIES = {
    "publish",
    "auth_mutation",
    "root",
    "hold",
    "event",
    "backup",
    "durable_ack",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get_path(document, dotted):
    value = document
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return MISSING
        value = value[part]
    return value


def resolve_ref(root_schema, ref):
    require(ref.startswith("#/$defs/"), f"unsupported schema ref {ref}")
    return root_schema["$defs"][ref.split("/")[-1]]


def validate_schema(instance, schema, root_schema, path="$"):
    """Small JSON-Schema subset used by config.schema.json."""
    errors = []
    if "$ref" in schema:
        return validate_schema(instance, resolve_ref(root_schema, schema["$ref"]), root_schema, path)
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in {schema['enum']!r}")
    kind = schema.get("type")
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
    }
    if kind in checks and not checks[kind](instance):
        return errors + [f"{path}: expected {kind}"]
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match {schema['pattern']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(instance, dict):
        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{path}: missing required {name}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in instance:
                if name not in properties:
                    errors.append(f"{path}: unexpected property {name}")
        for name, child in properties.items():
            if name in instance:
                errors.extend(validate_schema(instance[name], child, root_schema, f"{path}.{name}"))
    return errors


def condition_matches(document, condition):
    value = get_path(document, condition["path"])
    if "present" in condition:
        return (value is not MISSING) is condition["present"]
    if value is MISSING:
        return False
    if "equals" in condition:
        return value == condition["equals"]
    if "not_equals" in condition:
        return value != condition["not_equals"]
    if "in" in condition:
        return value in condition["in"]
    raise ValueError(f"unsupported condition {condition}")


def reject_rule_matches(document, rule):
    return all(
        any(condition_matches(document, child) for child in condition["any"])
        if "any" in condition else condition_matches(document, condition)
        for condition in rule["when_all"]
    )


def validate_snapshot():
    """Verify the frozen W0 design snapshot and the current protocol entry.

    `design_snapshot` is the immutable W0 body (no longer at
    `docs/design/12-state-services.md`); its bytes are checked against the
    recorded SHA-256/git blob and its checksum. `current_design` is the current
    fresh-install protocol entry, verified separately so a historical byte can
    never stand in for it again.
    """
    snapshot = load(STATE / "snapshot.json")
    design = snapshot["design_snapshot"]
    path = ROOT / design["file"]
    require(path.is_file(), f"missing design snapshot {path}")
    require(design["file"] != "docs/design/12-state-services.md",
            "the historical W0 body must stay archived, not at the current entry")
    data = path.read_bytes()
    require(len(data) == design["bytes"], "design snapshot byte length changed")
    require(hashlib.sha256(data).hexdigest() == design["checked_in_sha256"], "design snapshot hash changed")
    require(design["source_sha256"] == design["checked_in_sha256"], "snapshot was not copied verbatim")
    require(design.get("checked_in_blob") == git_blob_id(data), "design snapshot git blob changed")
    text = path.read_text(encoding="utf-8")
    require(design["baseline_commit"] in text, "baseline commit missing from design snapshot")
    require(snapshot["w0_artifacts"]["producer_inventory"] == "docs/design/state-services/producers.json", "producer path drift")
    for relative in snapshot["w0_artifacts"].values():
        require((ROOT / relative).is_file(), f"missing W0 artifact {relative}")
    current = snapshot["current_design"]
    current_path = ROOT / current["file"]
    require(current_path.is_file(), f"missing current design {current_path}")
    current_bytes = current_path.read_bytes()
    require(len(current_bytes) == current["bytes"], "current design byte length changed")
    require(hashlib.sha256(current_bytes).hexdigest() == current["checked_in_sha256"], "current design hash changed")
    require(git_blob_id(current_bytes) == current.get("checked_in_blob"), "current design git blob changed")
    require(current["source_sha256"] == current["checked_in_sha256"], "current design was not restored verbatim")
    current_text = current_path.read_text(encoding="utf-8")
    for phrase in current["required_phrases"]:
        require(phrase in current_text, f"current design lost required contract text {phrase!r}")
    return snapshot


def git_blob_id(data):
    """Git object id of a blob: SHA-1 over `blob <len>\0<data>`."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def declares_table(sql, name):
    # Inventory references are table names in these checked-in migrations.
    # Reject mere mentions/comments; this is a static DDL check, not SQL execution.
    sql = re.sub(r"/\*.*?\*/|--[^\n]*", "", sql, flags=re.S)
    pattern = (
        r"\b(?:CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|"
        r"ALTER\s+TABLE(?:\s+IF\s+EXISTS)?)\s+"
        rf'(?:[a-z_]+\.)?"?{re.escape(name)}"?\b'
    )
    return bool(re.search(pattern, sql, re.I))


def _validate_producer_entries():
    inventory = load(STATE / "producers.json")
    require(inventory["schema"] == "rootyard.state-services.producers/v1", "producer schema drift")
    require(set(inventory["categories"]) >= REQUIRED_CATEGORIES, "producer categories incomplete")
    seen = set()
    categories = {category: 0 for category in REQUIRED_CATEGORIES}
    for entry in inventory["entries"]:
        entry_id = entry["id"]
        require(entry_id not in seen, f"duplicate producer {entry_id}")
        seen.add(entry_id)
        category = entry["category"]
        require(category in REQUIRED_CATEGORIES, f"{entry_id}: unknown category {category}")
        require(entry["implementation"] in {"existing", "partial", "proposed"}, f"{entry_id}: invalid status")
        require(entry["authority_current"] and entry["authority_target"] and entry["durable_ack"], f"{entry_id}: incomplete mapping")
        require(entry["entrypoints"], f"{entry_id}: no source entrypoints")
        if entry["implementation"] != "proposed":
            categories[category] += 1
        for spec in entry["entrypoints"]:
            source = ROOT / spec["file"]
            require(source.is_file(), f"{entry_id}: missing {spec['file']}")
            body = source.read_text(encoding="utf-8")
            for symbol in spec["symbols"]:
                pattern = rf"\b(?:fn|struct|enum|const|static|mod)\s+{re.escape(symbol)}\b"
                require(re.search(pattern, body), f"{entry_id}: {symbol} not defined in {spec['file']}")
        migrations = entry.get("migrations", [])
        combined = ""
        for migration in migrations:
            path = ROOT / migration
            require(path.is_file(), f"{entry_id}: missing {migration}")
            combined += path.read_text(encoding="utf-8")
        for name in entry.get("schema_objects", []):
            require(declares_table(combined, name), f"{entry_id}: table {name} has no CREATE/ALTER definition in referenced migrations")
    for category, count in categories.items():
        require(count > 0, f"no implemented/partial producer for {category}")
    return inventory


def validate_deployment():
    contract = load(STATE / "deployment-contract.json")
    schema = load(STATE / "config.schema.json")
    profiles = {p["id"]: p for p in contract["profiles"]}
    selectable = {p["id"] for p in contract["profiles"] if p.get("selectable_now")}
    implemented = {p["id"] for p in contract["profiles"] if p["status"] == "implemented"}
    require(selectable == implemented, "selectable profiles must equal implemented profiles")
    require(set(schema["properties"]["profile"]["enum"]) == selectable, "schema profile enum differs from contract")
    ids = [r["id"] for r in contract["reject_rules"]]
    require(len(ids) == len(set(ids)), "duplicate reject rule")
    accepted = contract["config_validation"]["accepted_examples"]
    rejected = contract["config_validation"]["rejected_examples"]
    for relative in accepted:
        document = load(ROOT / relative)
        errors = validate_schema(document, schema, schema)
        errors += [f"{r['id']}: {r['reason']}" for r in contract["reject_rules"] if reject_rule_matches(document, r)]
        require(not errors, f"accepted example {relative} failed: {errors}")
    for relative in rejected:
        document = load(ROOT / relative)
        errors = validate_schema(document, schema, schema)
        errors += [f"{r['id']}: {r['reason']}" for r in contract["reject_rules"] if reject_rule_matches(document, r)]
        require(errors, f"rejected example {relative} unexpectedly passed")
    require(profiles["state-standalone"]["status"] == "proposed", "standalone must remain proposed")
    require(profiles["state-distributed"]["status"] == "proposed", "distributed must remain proposed")
    return contract

def validate_budgets():
    sys.path.insert(0, str(ROOT / "scripts"))
    import state_services_baseline as runner
    budgets = load(STATE / "budgets.json")
    require(budgets["schema"] == "rootyard.state-services.budgets/v1", "budget schema drift")
    seen = set()
    for budget in budgets["budgets"]:
        require(budget["id"] not in seen, f"duplicate budget {budget['id']}")
        seen.add(budget["id"])
        spec = runner.METRIC_REGISTRY.get(budget["metric"])
        require(spec is not None, f"{budget['id']}: metric not emitted by runner")
        require(budget["statistic"] in spec["statistics"], f"{budget['id']}: unsupported statistic")
        require(budget["unit"] == spec["unit"], f"{budget['id']}: unit drift")
        require(budget["decision"] in {"not_frozen", "frozen"}, f"{budget['id']}: invalid decision")
        if budget["decision"] == "not_frozen":
            require(budget["bound"] is None, f"{budget['id']}: unfrozen budget must not have a numeric bound")
        else:
            require(isinstance(budget["bound"], (int, float)) and budget["bound"] > 0, f"{budget['id']}: frozen budget needs positive bound")
            evidence = budgets.get("baseline_evidence")
            require(evidence and (ROOT / evidence).is_file(), f"{budget['id']}: frozen budget needs evidence")
            report = load(ROOT / evidence)
            metric = report["metrics"].get(budget["metric"], {})
            require(metric.get("status") == "measured", f"{budget['id']}: evidence is not measured")
    workload = load(STATE / "workloads" / "w0-bounded.json")
    require(workload["schema"] == "rootyard.state-services.workload/v1", "workload schema drift")
    bounds = workload["bounds"]
    git = workload["git"]
    require(git["repo_count"] * git["pushes_per_repo"] <= bounds["max_git_push_ops"], "git workload exceeds bound")
    require(git["cas_rounds"] * git["cas_concurrency"] <= bounds["max_cas_ops"], "CAS workload exceeds bound")
    require(bounds["wall_clock_seconds"] > 0 and bounds["max_temp_bytes"] > 0, "invalid workload bounds")
    return budgets


OVERLAY_SCHEMA = "rootyard.state-services.implementation-overlay/v1"
OVERLAY_FEATURE = "state-baseline-metrics"


def canonical_manifest_digest(document):
    """Stable digest of a parsed manifest, independent of formatting and comments."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def check_feature_only_overlay(overlay, parent):
    """Validate the recorded feature-only overlay on its frozen parent.

    `parent` is the frozen W0/phase-metrics input. The overlay record must name
    that exact commit, reference its manifest/lock hashes (never a relabelled
    child hash) and declare exactly one empty, default-OFF feature while the
    lockfile stays the parent's byte-for-byte. The parent manifest archive must
    match its frozen hash and semantic digest. This check never reads today's
    root `Cargo.toml`/`Cargo.lock`; the integrated manifest has its own explicit
    contract (`check_integrated_manifest`).
    """
    require(overlay.get("schema") == OVERLAY_SCHEMA, "implementation overlay schema drift")
    require(overlay.get("stack_base") == parent.get("commit"), "overlay must name the frozen parent commit")
    parent_bytes = (ROOT / parent["archived"]["Cargo.toml"]).read_bytes()
    require(hashlib.sha256(parent_bytes).hexdigest() == parent["files"]["Cargo.toml"],
            "archived parent manifest does not match its frozen hash")
    require(canonical_manifest_digest(parse_manifest(parent_bytes.decode("utf-8")))
            == overlay.get("parent_manifest_semantic_sha256"),
            "parent semantic hash does not describe the archived parent manifest")
    feature = overlay.get("feature") or {}
    name = feature.get("name")
    require(name == OVERLAY_FEATURE, f"an implementation overlay may only declare {OVERLAY_FEATURE}")
    require(feature.get("included") == [], "the overlay feature must be empty (no enabled sub-features)")
    require(feature.get("default_enabled") is False, "the overlay feature must be default-OFF")
    require(overlay.get("parent_manifest_sha256") == parent["files"]["Cargo.toml"],
            "overlay must reference the frozen parent manifest hash, never a relabelled child hash")
    require(overlay.get("parent_lock_sha256") == parent["files"]["Cargo.lock"],
            "overlay must reference the frozen parent lockfile hash")
    recorded = overlay.get("files") or {}
    require(set(recorded) <= {"Cargo.toml", "Cargo.lock"}, "overlay records unexpected Cargo files")
    require(recorded.get("Cargo.lock") == parent["files"]["Cargo.lock"],
            "the overlay record must keep the parent lockfile hash")
    if overlay.get("child_manifest_sha256") is not None:
        require(overlay.get("child_manifest_sha256") == recorded.get("Cargo.toml"),
                "overlay child manifest hash must match its recorded file hash")
    return overlay


def overlay_child_manifest(overlay, manifest_text):
    """Validate an explicitly supplied overlay-applied (child) manifest.

    Only the archived parent manifest plus exactly one empty, default-OFF
    feature is accepted. Focused tests use this with the archived parent plus
    mutations; it is never applied to today's integrated manifest, which is not
    derived from the frozen parent.
    """
    deps = load(STATE / "dependencies.json")
    parent = deps["current_stack_parent"]
    name = (overlay.get("feature") or {}).get("name")
    require(name == OVERLAY_FEATURE, f"an implementation overlay may only declare {OVERLAY_FEATURE}")
    parent_manifest = parse_manifest((ROOT / parent["archived"]["Cargo.toml"]).read_text(encoding="utf-8"))
    manifest = parse_manifest(manifest_text)
    _check_msrv(manifest, parent["declared_rust_version"], "an implementation overlay")
    features = manifest.get("features") or {}
    require(features.get(name) == [], "the overlay feature must stay empty")
    require(name not in (features.get("default") or []), "the overlay feature must not be enabled by default")
    reduced = json.loads(json.dumps(manifest))
    del reduced["features"][name]
    if not reduced["features"]:
        del reduced["features"]
    require(canonical_manifest_digest(reduced) == canonical_manifest_digest(parent_manifest),
            "current manifest differs from the frozen parent beyond the declared empty feature")
    return manifest


INTEGRATED_SCHEMA = "rootyard.state-services.integrated-manifest/v1"
SUPPORTED_RUST_VERSIONS = {"1.85", "1.88"}


def _version_matches(request, version):
    if version is None:
        return False
    try:
        have = tuple(int(part) for part in version.split("."))
    except ValueError:
        return False
    request = request.strip()
    if request.startswith("="):
        return version == request[1:].strip()
    if request.startswith("^"):
        request = request[1:].strip()
    try:
        want = tuple(int(part) for part in request.split("."))
    except ValueError:
        return False
    if not want:
        return False
    # Cargo caret/default semantics: same left-most non-zero component.
    return have[: len(want) - 1] == want[:-1] and have[len(want) - 1] >= want[-1]


def _dependency_ok(spec, expected):
    """Check one declared dependency spec against its recorded integrated shape."""
    if isinstance(spec, str):
        return _version_matches(spec, expected.get("version"))
    if not isinstance(spec, dict):
        return False
    if spec.get("optional", False) != expected.get("optional", False):
        return False
    if expected.get("path"):
        return "version" not in spec
    if spec.get("path") is not None:
        return False
    if expected.get("version") is not None and not _version_matches(spec.get("version", ""), expected["version"]):
        return False
    if "default_features" in expected and spec.get("default-features", True) != expected["default_features"]:
        return False
    if "features" in expected:
        have = set(spec.get("features") or [])
        if not set(expected["features"]) <= have:
            return False
    return True


def check_integrated_manifest(integrated, manifest_text, lock_text):
    """Validate today's integrated Cargo inputs explicitly against HEAD.

    The integrated branch legitimately carries new features and dependencies
    that the frozen W0 parent never had. This contract makes them explicit:
    every declared feature is either empty or a dependency-activating feature
    whose `dep:` target is exactly the declared feature name; dependencies are
    limited to the reviewed list; the recorded MSRV holds; and the lockfile is
    consistent with that manifest (expected packages present, and the only
    added packages relative to the frozen W0 lock are the recorded ones).
    """
    require(integrated.get("schema") == INTEGRATED_SCHEMA, "integrated manifest schema drift")
    manifest = parse_manifest(manifest_text)
    _check_msrv(manifest, integrated.get("declared_rust_version"), "current integrated manifest")
    if integrated.get("declared_rust_version") not in SUPPORTED_RUST_VERSIONS:
        raise ValueError("integrated manifest MSRV changed")
    features = manifest.get("features") or {}
    declared = integrated.get("features") or {}
    require(set(features) == set(declared), f"integrated features changed: {sorted(set(features) ^ set(declared))}")
    for name, spec in features.items():
        expected = declared[name]
        require(spec == expected.get("value"), f"feature {name} must stay {expected.get('value')!r}")
        if spec == []:
            continue
        if len(spec) != 1 or not spec[0].startswith("dep:"):
            raise ValueError(f"feature {name} must be empty or enable exactly its own optional dependency")
        crate = spec[0][len("dep:"):]
        require(crate in (manifest.get("dependencies") or {}), f"feature {name} activates undeclared {crate}")
        require((manifest["dependencies"][crate] or {}).get("optional") is True,
                f"feature {name} activates a non-optional dependency {crate}")
        require(crate == name or crate in expected.get("activates", []), f"feature {name} activates unexpected {crate}")
    default = features.get("default") or []
    for name in default:
        if name.startswith("dep:"):
            continue
        require(name in features, f"default features reference unknown {name}")
    for name, spec in (manifest.get("dependencies") or {}).items():
        if isinstance(spec, dict) and spec.get("optional") and f"dep:{name}" not in {v[0] for v in features.values() if v}:
            raise ValueError(f"optional dependency {name} has no enabling feature")
    for key, expected in (integrated.get("dependencies") or {}).items():
        table, _, name = key.partition(".")
        if table == "target":
            raise ValueError("target-specific integrated dependencies are not declared")
        require(table in ("dependencies", "dev-dependencies"), f"integrated dependency {key} uses an unreviewed table")
        spec = (manifest.get(table) or {}).get(name)
        require(spec is not None, f"integrated dependency {name} is missing")
        require(_dependency_ok(spec, expected), f"integrated dependency {name} changed")
    reviewed = set(integrated.get("dependencies") or {})
    actual = _dependency_entries(manifest)
    require(not any(key.startswith("patch.") for key in actual), "integrated manifest must not patch crates")
    for key in actual:
        if key not in reviewed:
            raise ValueError(f"unreviewed integrated dependency {key}")
    parent_lock = (ROOT / integrated["baseline_lock"]).read_text(encoding="utf-8")
    previous = lock_packages(parent_lock)
    present = lock_packages(lock_text)
    require(previous <= present, f"lockfile lost frozen packages: {sorted(previous - present)}")
    added = set(added_lock_packages(parent_lock, lock_text))
    allowed = set(integrated.get("lock_additions") or [])
    unreviewed = added - allowed
    require(not unreviewed, f"lockfile contains unreviewed additions: {sorted(unreviewed)[:10]}")
    return integrated


def validate_dependencies():
    deps = load(STATE / "dependencies.json")
    require(deps["schema"] == "rootyard.state-services.dependencies/v1", "dependency schema drift")
    baseline = deps["baseline"]
    require(baseline["declared_rust_version"] == "1.85", "historical baseline MSRV drift")
    require(baseline["planned_rust_version"] == "1.88", "planned MSRV must remain explicit")
    parent = check_historical_fixtures(deps)
    overlay = deps.get("implementation_overlay")
    if overlay is None:
        # No declared overlay: the original strict parent-hash gate applies.
        for filename, expected in parent["files"].items():
            require(sha256_file(ROOT / filename) == expected, f"current {filename} hash drift")
    else:
        check_feature_only_overlay(
            overlay, parent, (ROOT / "Cargo.toml").read_text(encoding="utf-8"),
            {"Cargo.toml": sha256_file(ROOT / "Cargo.toml")})
    integrated = deps.get("integrated_manifest")
    if integrated is None:
        raise ValueError("the integrated manifest contract is missing")
    check_integrated_manifest(
        integrated,
        (ROOT / "Cargo.toml").read_text(encoding="utf-8"),
        (ROOT / "Cargo.lock").read_text(encoding="utf-8"),
    )
    require(deps["selection_policy"]["w0_does_not_modify_cargo"], "W0 Cargo modification guard missing")
    lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    for crate, version in baseline["verified_locked_versions"].items():
        require(re.search(rf'name = "{re.escape(crate)}"\nversion = "{re.escape(version)}"', lock), f"locked version mismatch for {crate}")
    for candidate in deps["candidates"]:
        require(candidate["verification"] in {"verified_crates_io_metadata", "candidate_unverified"}, f"{candidate['crate']}: invalid verification")
        if candidate["verification"] == "verified_crates_io_metadata":
            require(candidate["version"] and candidate["license"], f"{candidate['crate']}: verified metadata incomplete")
        require(candidate["added_to_cargo_in_w0"] is False, f"{candidate['crate']}: dependency added in W0")
    return deps


def validate_all():
    snapshot = validate_snapshot()
    producers = validate_producers()
    contract = validate_deployment()
    budgets = validate_budgets()
    dependencies = validate_dependencies()
    return snapshot, producers, contract, budgets, dependencies

def _validate_producer_families(inventory):
    families = inventory.get("producer_families", [])
    require(families, "producer families are missing")
    family_ids = set()
    for family in families:
        require(family["id"] not in family_ids, f"duplicate family {family['id']}")
        family_ids.add(family["id"])
        require(family.get("logical_roots"), f"{family['id']}: roots missing")
        require(family.get("scope_dimensions"), f"{family['id']}: scope dimensions missing")
        require(family.get("gc_consumer") and family.get("backup_consumer"), f"{family['id']}: consumers missing")
        for spec in family["sources"]:
            source = ROOT / spec["file"]
            require(source.is_file(), f"{family['id']}: missing {spec['file']}")
            body = source.read_text(encoding="utf-8")
            for symbol in spec["symbols"]:
                pattern = rf"\b(?:fn|struct|enum|const|static|mod)\s+{re.escape(symbol)}\b"
                require(re.search(pattern, body), f"{family['id']}: {symbol} not defined in {spec['file']}")
    require(inventory.get("unresolved_producer_coverage"), "unresolved producer coverage must be explicit")
    return inventory

def validate_producers():
    inventory = _validate_producer_entries()
    _validate_producer_families(inventory)
    for key in ("logical_roots", "physical_holds", "auth_scopes"):
        require(inventory.get(key), f"{key} separation is missing")
        ids = [item["id"] for item in inventory[key]]
        require(len(ids) == len(set(ids)), f"duplicate {key} id")
    return inventory

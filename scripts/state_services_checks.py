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
    snapshot = load(STATE / "snapshot.json")
    design = snapshot["design_snapshot"]
    path = ROOT / design["file"]
    require(path.is_file(), f"missing design snapshot {path}")
    require(sha256_file(path) == design["checked_in_sha256"], "design snapshot hash changed")
    require(design["source_sha256"] == design["checked_in_sha256"], "snapshot was not copied verbatim")
    text = path.read_text(encoding="utf-8")
    require(design["baseline_commit"] in text, "baseline commit missing from design snapshot")
    require(snapshot["w0_artifacts"]["producer_inventory"] == "docs/design/state-services/producers.json", "producer path drift")
    for relative in snapshot["w0_artifacts"].values():
        require((ROOT / relative).is_file(), f"missing W0 artifact {relative}")
    return snapshot


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


def validate_dependencies():
    deps = load(STATE / "dependencies.json")
    require(deps["schema"] == "rootyard.state-services.dependencies/v1", "dependency schema drift")
    baseline = deps["baseline"]
    require(baseline["declared_rust_version"] == "1.85", "baseline MSRV drift")
    require(baseline["planned_rust_version"] == "1.88", "planned MSRV must remain explicit")
    require(sha256_file(ROOT / "Cargo.toml") == baseline["files"]["Cargo.toml"], "Cargo.toml hash drift")
    require(sha256_file(ROOT / "Cargo.lock") == baseline["files"]["Cargo.lock"], "Cargo.lock hash drift")
    require(sha256_file(ROOT / "LICENSE") == baseline["files"]["LICENSE"], "LICENSE hash drift")
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

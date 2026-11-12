#!/usr/bin/env python3
#
# Copyright (c) 2026 Contributors to the Eclipse Foundation.
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0
#
# Contributors:
#     Data In Motion - initial API and implementation
#
"""Validate CycloneDX / SPDX JSON files against local copies of the official schemas.

The schema directory holds bom-<version>.schema.json for every CycloneDX version written,
the files they reference (spdx.schema.json, jsf-0.82.schema.json, cryptography-defs.schema.json)
and spdx-2.3.schema.json. A CycloneDX file is checked against the schema of its specVersion,
anything else against SPDX 2.3. Exit code: number of invalid files.

usage: python3 -I validate-sbom.py <schema-dir> <file>...
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


def registry(schema_dir: Path) -> Registry:
    resources = []
    for path in schema_dir.glob("*.json"):
        contents = json.loads(path.read_text())
        resource = Resource.from_contents(contents, default_specification=DRAFT7)
        resources.append((path.name, resource))
        if "$id" in contents:
            resources.append((contents["$id"], resource))
    return Registry().with_resources(resources)


def main() -> int:
    schema_dir = Path(sys.argv[1])
    reg = registry(schema_dir)
    failed = 0
    for name in sys.argv[2:]:
        doc = json.loads(Path(name).read_text())
        if doc.get("bomFormat") == "CycloneDX":
            schema_file = schema_dir / f"bom-{doc['specVersion']}.schema.json"
        else:
            schema_file = schema_dir / "spdx-2.3.schema.json"
        schema = json.loads(schema_file.read_text())
        cls = Draft202012Validator if "2020-12" in schema.get("$schema", "") else Draft7Validator
        errors = sorted(cls(schema, registry=reg).iter_errors(doc), key=lambda e: list(e.absolute_path))
        print(f"{name}: {schema_file.name}: {'OK' if not errors else str(len(errors)) + ' error(s)'}")
        for error in errors[:15]:
            print("   ", "/".join(str(p) for p in error.absolute_path), "-", error.message[:200])
        failed += bool(errors)
    return failed


if __name__ == "__main__":
    sys.exit(main())

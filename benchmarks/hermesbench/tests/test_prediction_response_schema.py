# Verifies the pinned Codex output schema stays within the accepted JSON Schema subset.

from __future__ import annotations

import json
import unittest
from pathlib import Path


class PredictionResponseSchemaTests(unittest.TestCase):
    def _schema(self) -> dict[str, object]:
        schema_path = Path(__file__).parents[1] / "schemas" / "prediction-response.schema.json"
        return json.loads(schema_path.read_text(encoding="utf-8"))

    def test_location_line_uses_anyof_for_equivalent_integer_or_range_shape(self) -> None:
        schema = self._schema()
        line = schema["$defs"]["location"]["properties"]["line"]

        self.assertNotIn("oneOf", line)
        self.assertEqual(
            line["anyOf"],
            [
                {"type": "integer", "minimum": 1},
                {"type": "string", "pattern": "^[1-9][0-9]*-[1-9][0-9]*$"},
            ],
        )

    def test_schema_uses_only_supported_object_and_scalar_keywords(self) -> None:
        schema = self._schema()
        objects: list[dict[str, object]] = []
        any_of_branches: list[dict[str, object]] = []

        def visit(value: object) -> None:
            if isinstance(value, dict):
                self.assertNotIn("oneOf", value)
                self.assertNotIn("minLength", value)
                if value.get("type") == "object":
                    objects.append(value)
                if "anyOf" in value:
                    branches = value["anyOf"]
                    self.assertIsInstance(branches, list)
                    any_of_branches.extend(branches)
                for nested in value.values():
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(schema)
        self.assertEqual(schema["properties"]["schema_version"], {"type": "integer", "const": 1})
        self.assertTrue(objects)
        for object_schema in objects:
            self.assertFalse(object_schema.get("additionalProperties"))
            self.assertEqual(set(object_schema.get("required", [])), set(object_schema.get("properties", {})))
        self.assertTrue(any_of_branches)
        self.assertTrue(all(isinstance(branch.get("type"), str) for branch in any_of_branches))


if __name__ == "__main__":
    unittest.main()

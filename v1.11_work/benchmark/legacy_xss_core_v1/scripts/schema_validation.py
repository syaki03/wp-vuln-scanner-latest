import re
from datetime import date
from urllib.parse import urlparse


def _resolve(root, ref):
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported schema ref: {ref}")
    value = root
    for part in ref[2:].split("/"):
        value = value[part.replace("~1", "/").replace("~0", "~")]
    return value


def _matches_type(value, expected):
    checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    return checks.get(expected, lambda _item: False)(value)


def validate(instance, schema, root=None, path="$", errors=None):
    root = root or schema
    errors = errors if errors is not None else []
    if "$ref" in schema:
        return validate(instance, _resolve(root, schema["$ref"]), root, path, errors)
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: not in enum {schema['enum']!r}")
    if "type" in schema:
        expected = schema["type"]
        choices = expected if isinstance(expected, list) else [expected]
        if not any(_matches_type(instance, choice) for choice in choices):
            errors.append(f"{path}: expected type {expected!r}")
            return errors
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key}")
        for key, child_schema in properties.items():
            if key in instance:
                validate(instance[key], child_schema, root, f"{path}.{key}", errors)
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than minItems")
        if "items" in schema:
            for index, item in enumerate(instance):
                validate(item, schema["items"], root, f"{path}[{index}]", errors)
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than minLength")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern")
        if schema.get("format") == "uri":
            parsed = urlparse(instance)
            if parsed.scheme != "https" or not parsed.netloc:
                errors.append(f"{path}: expected HTTPS URI")
        if schema.get("format") == "date":
            try:
                date.fromisoformat(instance)
            except ValueError:
                errors.append(f"{path}: expected ISO date")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum")
    return errors

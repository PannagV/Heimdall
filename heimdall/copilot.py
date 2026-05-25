import json
from typing import Dict, List, Optional

import requests

try:
    from jsonschema import Draft7Validator
except ImportError:  # pragma: no cover - optional dependency
    Draft7Validator = None  # type: ignore[assignment]

from .config import DEFAULT_CONFIG
from .hces import normalize_iso_timestamp


COPILOT_ALLOWED_FIELDS = [
    "event_id",
    "timestamp",
    "source_type",
    "event.kind",
    "event.category",
    "event.type",
    "event.severity",
    "event.outcome",
    "machine.id",
    "machine.name",
    "machine.group",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "network.protocol",
    "network.transport",
    "network.direction",
    "alert.id",
    "alert.signature",
    "alert.category",
    "alert.severity",
    "alert.action",
    "incident.id",
    "incident.status",
    "incident.priority",
    "attack.tactic",
    "attack.technique",
    "attack.technique_id",
    "user.name",
    "file.name",
    "file.hash.sha256",
    "raw_event.source",
]


def build_projection(fields: List[str]) -> Dict[str, int]:
    projection: Dict[str, int] = {"_id": 0}
    for field in fields:
        projection[field] = 1
    return projection


COPILOT_EVENT_PROJECTION = build_projection(COPILOT_ALLOWED_FIELDS)


COPILOT_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["severity", "mitre", "boundedness"],
    "properties": {
        "severity": {
            "type": "object",
            "required": ["score", "label", "reasons"],
            "properties": {
                "score": {"type": "number"},
                "label": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
        "mitre": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tactic", "technique", "technique_id", "reasons"],
                "properties": {
                    "tactic": {"type": "string"},
                    "technique": {"type": "string"},
                    "technique_id": {"type": "string"},
                    "reasons": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": True,
            },
        },
        "boundedness": {
            "type": "object",
            "required": ["evidence_ids", "notes"],
            "properties": {
                "evidence_ids": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


COPILOT_VALIDATOR = Draft7Validator(COPILOT_OUTPUT_SCHEMA) if Draft7Validator else None


class CopilotError(Exception):
    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _get_value(payload: Dict, path: str) -> Optional[object]:
    current: object = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _set_value(target: Dict, path: str, value: object) -> None:
    current = target
    parts = path.split(".")
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def filter_event(event: Dict) -> Dict:
    filtered: Dict[str, object] = {}
    for path in COPILOT_ALLOWED_FIELDS:
        value = _get_value(event, path)
        if value is not None:
            _set_value(filtered, path, value)
    return filtered


def _event_sort_key(event: Dict) -> str:
    timestamp = event.get("timestamp")
    normalized = normalize_iso_timestamp(timestamp)
    return normalized or (timestamp or "")


def build_prompt(events: List[Dict], event_ids: List[str]) -> List[Dict[str, str]]:
    evidence_json = json.dumps(events, ensure_ascii=True, separators=(",", ":"))
    system = (
        "You are the Heimdall AI SOC Copilot. Use ONLY the provided evidence list. "
        "Return a single JSON object that matches the requested schema. "
        "Do not add commentary, markdown, or code fences."
    )
    user = (
        "Analyze the event chain and return severity scoring, MITRE ATT&CK mapping, "
        "and explainable reasoning. The evidence is already ordered by timestamp. "
        "If evidence is insufficient, choose low severity and explain why.\n\n"
        "Required JSON schema:\n"
        "{\n"
        "  \"severity\": {\"score\": number, \"label\": string, \"reasons\": [string]},\n"
        "  \"mitre\": [{\"tactic\": string, \"technique\": string, \"technique_id\": string, \"reasons\": [string]}],\n"
        "  \"boundedness\": {\"evidence_ids\": [string], \"notes\": string}\n"
        "}\n\n"
        f"Evidence IDs: {event_ids}\n"
        f"Evidence: {evidence_json}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _extract_json_block(text: str) -> Dict:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise CopilotError("model response did not include JSON", 502)
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise CopilotError(f"failed to parse model JSON: {exc}", 502)


def _parse_model_response(data: Dict) -> Dict:
    if isinstance(data, dict) and "choices" in data and data.get("choices"):
        message = data["choices"][0].get("message", {})
        content = message.get("content") or ""
        if isinstance(content, dict):
            return content
        return _extract_json_block(str(content))
    if isinstance(data, dict):
        return data
    raise CopilotError("unexpected model response", 502)


def _validate_response(parsed: Dict) -> None:
    if not COPILOT_VALIDATOR:
        return
    errors = sorted(COPILOT_VALIDATOR.iter_errors(parsed), key=lambda e: e.path)
    if errors:
        message = errors[0].message
        raise CopilotError(f"copilot response validation failed: {message}", 502)


def _normalize_boundedness(parsed: Dict, event_ids: List[str]) -> Dict:
    bounded = parsed.get("boundedness")
    if not isinstance(bounded, dict):
        bounded = {}
        parsed["boundedness"] = bounded
    evidence_ids = bounded.get("evidence_ids")
    if not isinstance(evidence_ids, list) or any(
        not isinstance(item, str) or item not in event_ids for item in evidence_ids
    ):
        bounded["evidence_ids"] = list(event_ids)
    notes = bounded.get("notes")
    if not isinstance(notes, str) or not notes.strip():
        bounded["notes"] = "Only the selected evidence was used."
    return parsed


def _invoke_model(messages: List[Dict[str, str]], config: Dict) -> Dict:
    provider = (config.get("copilot_provider") or "").strip().lower()
    base_url = (config.get("copilot_base_url") or "").strip().rstrip("/")
    api_key = (config.get("copilot_api_key") or "").strip()
    model = (config.get("copilot_model") or "").strip()
    if not base_url:
        raise CopilotError("copilot base_url is not configured", 500)
    if not model:
        raise CopilotError("copilot model is not configured", 500)

    url = f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if provider == "cloud" and api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    timeout = max(5, int(config.get("copilot_timeout_seconds") or 20))
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        raise CopilotError(f"copilot request failed: {exc}", 502)

    if response.status_code >= 300:
        message = response.text.strip()
        if len(message) > 300:
            message = message[:300] + "..."
        raise CopilotError(f"copilot provider error ({response.status_code}): {message}", 502)

    try:
        return response.json()
    except ValueError as exc:
        raise CopilotError(f"copilot response was not JSON: {exc}", 502)


def analyze_copilot(events: List[Dict], event_ids: List[str], config: Optional[Dict] = None) -> Dict:
    config = config or DEFAULT_CONFIG
    if not event_ids:
        raise CopilotError("no events selected", 400)

    max_events = max(1, int(config.get("copilot_max_events") or 50))
    if len(event_ids) > max_events:
        raise CopilotError(f"too many events selected (max {max_events})", 413)

    filtered_events = [filter_event(event) for event in events]
    filtered_events = sorted(filtered_events, key=_event_sort_key)
    payload_bytes = json.dumps(filtered_events, ensure_ascii=True).encode("utf-8")
    max_bytes = max(1, int(config.get("copilot_max_bytes") or 200000))
    if len(payload_bytes) > max_bytes:
        raise CopilotError("selected evidence is too large", 413)

    messages = build_prompt(filtered_events, event_ids)
    response_data = _invoke_model(messages, config)
    parsed = _parse_model_response(response_data)
    _validate_response(parsed)
    return _normalize_boundedness(parsed, event_ids)

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from .config import DEFAULT_CONFIG

logger = logging.getLogger(__name__)


def priority_rank(priority: str) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(priority or "low", 1)


def map_priority_to_jira(priority: str) -> str:
    mapping = {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Highest",
    }
    return mapping.get(priority or "medium", "Medium")


def jira_status_for_incident(status: str) -> str:
    mapping = {
        "open": "New",
        "triaged": "Triaged",
        "investigating": "Investigating",
        "contained": "Contained",
        "resolved": "Resolved",
        "closed": "Resolved",
    }
    return mapping.get(status or "open", "New")


def slack_severity_emoji(priority: str) -> str:
    mapping = {"critical": "🔥", "high": "⚠️", "medium": "ℹ️", "low": "ℹ️"}
    return mapping.get(priority or "medium", "ℹ️")


def slack_escalation_emoji() -> str:
    return "🆙"


def safe_join(values: List[object]) -> str:
    return ", ".join(str(value) for value in values if value) or "-"


def build_summary(incident: Dict) -> str:
    category = incident.get("category") or "Activity"
    source_ips = safe_join(incident.get("entities", {}).get("source_ips", []))
    return f"[Heimdall] {category} detected from {source_ips}"


def build_description(incident: Dict, enrich: Dict) -> str:
    return (
        "h2. Incident Overview\n"
        f"*Heimdall Incident ID:* {incident.get('incident_id', '-') }\n"
        "*Detected By:* Heimdall SIEM\n"
        f"*First Seen:* {incident.get('first_seen', '-') }\n"
        f"*Last Seen:* {incident.get('last_seen', '-') }\n"
        f"*Severity:* {incident.get('priority', '-') }\n"
        f"*Category:* {incident.get('category', '-') }\n\n"
        "h2. Correlation Details\n"
        f"*Triggered Rule(s):* {safe_join(incident.get('rule_ids', []))}\n"
        f"*Event Count:* {enrich.get('event_count', 0)}\n"
        f"*Source IP(s):* {safe_join(incident.get('entities', {}).get('source_ips', []))}\n"
        f"*Destination IP(s):* {safe_join(incident.get('entities', {}).get('destination_ips', []))}\n\n"
        "h2. Detection Summary\n"
        f"*Top Signature:* {enrich.get('top_signature', '-') }\n"
        f"*Protocol(s):* {safe_join(enrich.get('protocols', []))}\n\n"
        "h2. MITRE ATT&CK\n"
        f"*Tactic:* {enrich.get('attack_tactic', '-') }\n"
        f"*Technique:* {enrich.get('attack_technique', '-') } ({enrich.get('attack_technique_id', '-') })\n\n"
        "h2. Recommended Actions\n"
        "- Validate source host legitimacy\n"
        "- Assess scope of impact\n"
        "- Monitor for follow-on activity\n\n"
        "h2. Heimdall References\n"
        f"*Internal Incident ID:* {incident.get('incident_id', '-') }"
    )


def build_adf_description(incident: Dict, enrich: Dict) -> Dict:
    text = build_description(incident, enrich)
    paragraphs = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in text.split("\n")
    ]
    return {"type": "doc", "version": 1, "content": paragraphs}


class JiraSlackIntegration:
    def __init__(self, events_collection, incidents_collection, mongo_lock, incidents_lock) -> None:
        self.events_collection = events_collection
        self.incidents_collection = incidents_collection
        self.mongo_lock = mongo_lock
        self.incidents_lock = incidents_lock

    def enabled(self) -> bool:
        return bool(DEFAULT_CONFIG["jira_base_url"] and DEFAULT_CONFIG["jira_api_token"])

    def slack_enabled(self) -> bool:
        return bool(DEFAULT_CONFIG["slack_webhook_url"])

    def min_priority_met(self, priority: str) -> bool:
        threshold = DEFAULT_CONFIG["integration_min_priority"]
        return priority_rank(priority) >= priority_rank(threshold)

    def enrich_incident(self, incident: Dict) -> Dict:
        event_refs = incident.get("event_refs", [])
        event_count = len(event_refs)
        protocols = set()
        signatures = {}
        attack_tactic = None
        attack_technique = None
        attack_technique_id = None

        if self.events_collection is None or not event_refs:
            return {
                "event_count": event_count,
                "protocols": [],
                "top_signature": "-",
                "attack_tactic": attack_tactic or "-",
                "attack_technique": attack_technique or "-",
                "attack_technique_id": attack_technique_id or "-",
            }

        try:
            with self.mongo_lock:
                cursor = self.events_collection.find(
                    {"event_id": {"$in": event_refs}},
                    {"alert.signature": 1, "network.protocol": 1, "attack": 1},
                )
                for event in cursor:
                    signature = event.get("alert", {}).get("signature")
                    if signature:
                        signatures[signature] = signatures.get(signature, 0) + 1
                    protocol = event.get("network", {}).get("protocol")
                    if protocol:
                        protocols.add(protocol)
                    attack = event.get("attack", {}) or {}
                    if not attack_tactic:
                        attack_tactic = attack.get("tactic")
                    if not attack_technique:
                        attack_technique = attack.get("technique")
                    if not attack_technique_id:
                        attack_technique_id = attack.get("technique_id")
        except Exception:
            pass

        top_signature = "-"
        if signatures:
            top_signature = max(signatures.items(), key=lambda item: item[1])[0]

        return {
            "event_count": event_count,
            "protocols": sorted(protocols),
            "top_signature": top_signature,
            "attack_tactic": attack_tactic or "-",
            "attack_technique": attack_technique or "-",
            "attack_technique_id": attack_technique_id or "-",
        }

    def build_jira_payload(self, incident: Dict, enrich: Dict) -> Dict:
        summary = build_summary(incident)
        description = build_adf_description(incident, enrich)
        fields = {
            "project": {"key": DEFAULT_CONFIG["jira_project_key"]},
            "summary": summary,
            "description": description,
            "issuetype": {"name": DEFAULT_CONFIG["jira_issue_type"]},
            "priority": {"name": map_priority_to_jira(incident.get("priority"))},
            "labels": ["heimdall", incident.get("category") or "incident"],
        }

        if DEFAULT_CONFIG["jira_field_heimdall_id"]:
            fields[DEFAULT_CONFIG["jira_field_heimdall_id"]] = incident.get("incident_id")
        if DEFAULT_CONFIG["jira_field_source_ips"]:
            fields[DEFAULT_CONFIG["jira_field_source_ips"]] = safe_join(
                incident.get("entities", {}).get("source_ips", [])
            )
        if DEFAULT_CONFIG["jira_field_event_count"]:
            fields[DEFAULT_CONFIG["jira_field_event_count"]] = enrich.get("event_count", 0)

        return {"fields": fields}

    def jira_headers(self) -> Dict:
        token = DEFAULT_CONFIG["jira_api_token"]
        email = DEFAULT_CONFIG["jira_email"]
        if email:
            raw = f"{email}:{token}".encode("utf-8")
            auth = base64.b64encode(raw).decode("utf-8")
            auth_header = f"Basic {auth}"
        else:
            auth_header = f"Bearer {token}"
        return {
            "Authorization": auth_header,
            "Content-Type": "application/json",
        }

    def jira_issue_key(self, incident: Dict) -> Optional[str]:
        jira_block = incident.get("jira") or {}
        return jira_block.get("issue_key") or incident.get("jira_issue_key")

    def jira_issue_url(self, incident: Dict) -> Optional[str]:
        jira_block = incident.get("jira") or {}
        return jira_block.get("issue_url") or incident.get("jira_issue_url")

    def _log_jira_config_status(self) -> None:
        if not self.enabled():
            logger.warning("[JIRA] Disabled - missing base URL or API token")
            return
        base_url = DEFAULT_CONFIG["jira_base_url"].rstrip("/")
        if "atlassian.net" not in base_url:
            logger.warning("[JIRA] Base URL may be invalid: %s", base_url)
        try:
            response = requests.get(
                f"{base_url}/rest/api/3/myself",
                headers=self.jira_headers(),
                timeout=8,
            )
            if response.status_code >= 300:
                logger.error("[JIRA] Connection failed: %s %s", response.status_code, response.text)
                return
            logger.info("[JIRA] Connected successfully")
        except Exception as exc:
            logger.error("[JIRA] Connection failed: %s", exc)
            return

        project_key = DEFAULT_CONFIG["jira_project_key"]
        try:
            response = requests.get(
                f"{base_url}/rest/api/3/project/{project_key}",
                headers=self.jira_headers(),
                timeout=8,
            )
            if response.status_code >= 300:
                logger.error("[JIRA] Project lookup failed: %s %s", response.status_code, response.text)
            else:
                data = response.json()
                logger.info("[JIRA] Project resolved: %s", data.get("key", project_key))
        except Exception as exc:
            logger.error("[JIRA] Project lookup failed: %s", exc)

        issue_type = DEFAULT_CONFIG["jira_issue_type"]
        try:
            response = requests.get(
                f"{base_url}/rest/api/3/issuetype",
                headers=self.jira_headers(),
                timeout=8,
            )
            if response.status_code >= 300:
                logger.error("[JIRA] Issue type lookup failed: %s %s", response.status_code, response.text)
                return
            types = response.json()
            match = next((item for item in types if item.get("name") == issue_type), None)
            if match:
                logger.info("[JIRA] Issue type resolved: %s (id=%s)", match.get("name"), match.get("id"))
            else:
                logger.error("[JIRA] Issue type not found: %s", issue_type)
        except Exception as exc:
            logger.error("[JIRA] Issue type lookup failed: %s", exc)

    def _utc_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _mark_slack_notified(self, incident_id: str, resolved: bool = False) -> None:
        if not self.incidents_collection:
            return
        update = {
            "$set": {
                "notifications.slack_notified": True,
                "notifications.last_slack_update": self._utc_iso(),
            }
        }
        if resolved:
            update["$set"]["notifications.slack_resolved"] = True
        try:
            with self.incidents_lock:
                self.incidents_collection.update_one(
                    {"incident_id": incident_id},
                    update,
                )
        except Exception:
            return

    def _mark_jira_failed(self, incident_id: Optional[str], error: str) -> None:
        if not incident_id or not self.incidents_collection:
            return
        try:
            with self.incidents_lock:
                self.incidents_collection.update_one(
                    {"incident_id": incident_id},
                    {"$set": {"jira.creation_failed": True, "jira.last_error": error}},
                )
        except Exception:
            return

    def create_jira_issue(self, incident: Dict) -> Optional[Dict]:
        if not self.enabled() or not self.min_priority_met(incident.get("priority")):
            return None
        if self.jira_issue_key(incident):
            return None
        if incident.get("jira", {}).get("creation_failed"):
            return None

        enrich = self.enrich_incident(incident)
        payload = self.build_jira_payload(incident, enrich)
        url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/rest/api/3/issue"

        try:
            response = requests.post(url, headers=self.jira_headers(), json=payload, timeout=8)
            if response.status_code >= 300:
                logger.error("[JIRA] Issue creation failed: %s %s", response.status_code, response.text)
                self._mark_jira_failed(incident.get("incident_id"), response.text)
                return None
            data = response.json()
        except Exception:
            logger.exception("[JIRA] Issue creation failed")
            self._mark_jira_failed(incident.get("incident_id"), "request failed")
            return None

        issue_key = data.get("key")
        if not issue_key:
            self._mark_jira_failed(incident.get("incident_id"), "missing issue key")
            return None

        issue_url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/browse/{issue_key}"
        try:
            with self.incidents_lock:
                self.incidents_collection.update_one(
                    {"incident_id": incident.get("incident_id")},
                    {
                        "$set": {
                            "jira": {
                                "issue_key": issue_key,
                                "issue_url": issue_url,
                                "creation_failed": False,
                                "last_error": None,
                            },
                            "jira_issue_key": issue_key,
                            "jira_issue_url": issue_url,
                        }
                    },
                )
        except Exception:
            pass

        self.send_slack_creation(incident, enrich, issue_url)
        return {"issue_key": issue_key, "issue_url": issue_url}

    def update_jira_issue(self, incident: Dict) -> None:
        if not self.enabled():
            return
        issue_key = self.jira_issue_key(incident)
        if not issue_key:
            return

        enrich = self.enrich_incident(incident)
        payload = self.build_jira_payload(incident, enrich)
        url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/rest/api/3/issue/{issue_key}"
        try:
            response = requests.put(url, headers=self.jira_headers(), json=payload, timeout=8)
            if response.status_code >= 300:
                logger.error("[JIRA] Issue update failed: %s %s", response.status_code, response.text)
        except Exception:
            logger.exception("[JIRA] Issue update failed")

        self.transition_jira(issue_key, jira_status_for_incident(incident.get("status")))

    def transition_jira(self, issue_key: str, target_status: str) -> None:
        url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/rest/api/3/issue/{issue_key}/transitions"
        try:
            response = requests.get(url, headers=self.jira_headers(), timeout=8)
            if response.status_code >= 300:
                logger.error("[JIRA] Transition lookup failed: %s %s", response.status_code, response.text)
                return
            data = response.json()
            transitions = data.get("transitions", [])
            transition_id = None
            for transition in transitions:
                if transition.get("name") == target_status:
                    transition_id = transition.get("id")
                    break
            if not transition_id:
                logger.error("[JIRA] Transition not found: %s", target_status)
                return
            payload = {"transition": {"id": transition_id}}
            update_response = requests.post(url, headers=self.jira_headers(), json=payload, timeout=8)
            if update_response.status_code >= 300:
                logger.error(
                    "[JIRA] Transition update failed: %s %s",
                    update_response.status_code,
                    update_response.text,
                )
        except Exception:
            logger.exception("[JIRA] Transition update failed")
            return

    def send_slack_creation(self, incident: Dict, enrich: Dict, jira_issue_url: str = "") -> bool:
        if not self.slack_enabled() or not self.min_priority_met(incident.get("priority")):
            return False
        notifications = incident.get("notifications", {}) or {}
        if notifications.get("slack_notified"):
            return False
        event_count = incident.get("event_count") or enrich.get("event_count", 0)
        payload = {
            "text": ":rotating_light: *New Security Incident Detected*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Category:* {incident.get('category', '-') }\n"
                            f"*Severity:* {incident.get('priority', '-') }\n"
                            f"*Source IP:* {safe_join(incident.get('entities', {}).get('source_ips', []))}\n"
                            f"*Event Count:* {event_count}"
                        ),
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Heimdall Incident ID:* {incident.get('incident_id', '-') }\n"
                            f"*Status:* {incident.get('status', 'open')}"
                        ),
                    },
                },
            ],
        }
        if jira_issue_url:
            payload["blocks"].append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View in Jira"},
                            "url": jira_issue_url,
                        }
                    ],
                }
            )
        if DEFAULT_CONFIG["slack_channel"]:
            payload["channel"] = DEFAULT_CONFIG["slack_channel"]

        try:
            requests.post(DEFAULT_CONFIG["slack_webhook_url"], json=payload, timeout=6)
        except Exception:
            return False
        incident_id = incident.get("incident_id")
        if incident_id:
            self._mark_slack_notified(incident_id)
        return True

    def send_slack_update(self, incident: Dict, update_type: str) -> None:
        if not self.slack_enabled():
            return
        notifications = incident.get("notifications", {}) or {}
        if not notifications.get("slack_notified"):
            return
        status = incident.get("status", "open")
        if update_type == "priority":
            emoji = slack_escalation_emoji()
            message_title = "*Incident Severity Escalated*"
        elif update_type == "status" and status == "closed":
            emoji = "✅"
            message_title = "*Incident Resolved*"
            if notifications.get("slack_resolved"):
                return
        else:
            return

        event_count = incident.get("event_count") or 0
        severity = incident.get("priority", "-")
        duration = "-"
        first_seen = incident.get("first_seen")
        last_seen = incident.get("last_seen")
        if first_seen and last_seen:
            try:
                start = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                end = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                delta = end - start if end >= start else start - end
                duration = str(delta).split(".")[0]
            except Exception:
                duration = "-"
        jira_url = self.jira_issue_url(incident) or ""
        text = f"{emoji} {message_title}: {incident.get('incident_id', '-') }"
        payload = {
            "text": text,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} {message_title}\n"
                            f"*ID:* {incident.get('incident_id', '-') }\n"
                            f"*Severity:* {severity}\n"
                            f"*Status:* {status}\n"
                            f"*Event Count:* {event_count}"
                        ),
                    },
                }
            ],
        }
        if update_type == "status" and status == "closed":
            payload["blocks"].append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Duration:* {duration}",
                    },
                }
            )
        if jira_url:
            payload["blocks"].append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View in Jira"},
                            "url": jira_url,
                        }
                    ],
                }
            )
        if DEFAULT_CONFIG["slack_channel"]:
            payload["channel"] = DEFAULT_CONFIG["slack_channel"]

        try:
            requests.post(DEFAULT_CONFIG["slack_webhook_url"], json=payload, timeout=6)
        except Exception:
            return
        incident_id = incident.get("incident_id")
        if incident_id:
            self._mark_slack_notified(incident_id, resolved=update_type == "status" and status == "closed")

    def on_incident_created(self, incident: Dict) -> None:
        if self.enabled():
            result = self.create_jira_issue(incident)
            if result:
                return
        if self.slack_enabled() and self.min_priority_met(incident.get("priority")):
            enrich = self.enrich_incident(incident)
            self.send_slack_creation(incident, enrich, "")

    def on_incident_updated(self, incident: Dict, reason: str) -> None:
        if self.enabled():
            if self.jira_issue_key(incident):
                self.update_jira_issue(incident)
        if reason in ("priority", "status"):
            self.send_slack_update(incident, reason)

    def bootstrap(self) -> None:
        self._log_jira_config_status()

from typing import Optional, Tuple

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from .correlation import INCIDENTS_MONGO_VALIDATOR
from .hces import HCES_MONGO_VALIDATOR


def init_mongo(mongo_uri: str) -> Tuple[Optional[MongoClient], Optional[object], Optional[object]]:
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
    except PyMongoError:
        return None, None, None

    db = client["alerts"]

    existing = list(db.list_collections(filter={"name": "events"}))
    if not existing:
        try:
            db.create_collection(
                "events",
                validator=HCES_MONGO_VALIDATOR,
                validationLevel="moderate",
            )
        except PyMongoError:
            return client, db["events"], None
    else:
        options = existing[0].get("options", {})
        validator = options.get("validator")
        if validator != HCES_MONGO_VALIDATOR:
            try:
                db.command(
                    "collMod",
                    "events",
                    validator=HCES_MONGO_VALIDATOR,
                    validationLevel="moderate",
                )
            except PyMongoError:
                pass

    incidents_existing = list(db.list_collections(filter={"name": "incidents"}))
    if not incidents_existing:
        try:
            db.create_collection(
                "incidents",
                validator=INCIDENTS_MONGO_VALIDATOR,
                validationLevel="moderate",
            )
        except PyMongoError:
            pass
    else:
        options = incidents_existing[0].get("options", {})
        validator = options.get("validator")
        if validator != INCIDENTS_MONGO_VALIDATOR:
            try:
                db.command(
                    "collMod",
                    "incidents",
                    validator=INCIDENTS_MONGO_VALIDATOR,
                    validationLevel="moderate",
                )
            except PyMongoError:
                pass

    events_collection = db["events"]
    incidents_collection = db["incidents"]

    try:
        events_collection.create_index("timestamp")
        events_collection.create_index("source.ip")
        events_collection.create_index("destination.ip")
        events_collection.create_index("event.severity")
        events_collection.create_index("alert.id")
        events_collection.create_index("incident.id")
    except PyMongoError:
        pass

    try:
        incidents_collection.create_index("status")
        incidents_collection.create_index("last_seen")
        incidents_collection.create_index("entities.source_ips")
        incidents_collection.create_index("entities.users")
        incidents_collection.create_index("rule_ids")
    except PyMongoError:
        pass

    return client, events_collection, incidents_collection

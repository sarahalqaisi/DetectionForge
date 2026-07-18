#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.database import SessionLocal, init_db
from app.services.rules import import_rules


if __name__ == "__main__":
    init_db()
    with SessionLocal() as db:
        created, updated = import_rules(db)
    print(f"Database initialized. Rules created: {created}; updated: {updated}.")

#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import settings
from app.database import Base, engine
from app import models  # noqa: F401


if __name__ == "__main__":
    if not settings.database_url.startswith("sqlite"):
        raise SystemExit("reset_db.py only supports the local SQLite database.")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Database reset. Run scripts/seed_demo.py to load demo data.")

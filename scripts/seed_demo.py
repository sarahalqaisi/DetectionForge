#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse

from app.database import SessionLocal, init_db
from app.services.seed import seed_demo


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load safe DetectionForge demo telemetry.")
    parser.add_argument("--force", action="store_true", help="Seed even when events already exist")
    args = parser.parse_args()
    init_db()
    with SessionLocal() as db:
        result = seed_demo(db, force=args.force)
    print(result)

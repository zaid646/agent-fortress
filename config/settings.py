import os

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG_PATH = os.environ.get("AF_CATALOG", os.path.join(ROOT, "attacks", "catalog.yaml"))
EVIDENCE_DIR = os.environ.get("AF_EVIDENCE", os.path.join(ROOT, "evidence"))
REPORT_DIR = os.environ.get("AF_REPORT", os.path.join(ROOT, "report"))
CORPUS_DIR = os.environ.get("AF_CORPUS", os.path.join(ROOT, "data", "corpus"))
TARGET_WORKSPACE = os.environ.get("AF_TARGET_WS", os.path.join(ROOT, "data", "sandbox"))
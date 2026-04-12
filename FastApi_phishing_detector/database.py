import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scan_history.db")

engine = create_engine(
    f"sqlite:///{DB_PATH}", 
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    """Represents a single URL scan record."""
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False, index=True)
    verdict = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False)
    scan_time = Column(Float, nullable=False)
    predictions_json = Column(Text, nullable=False)
    nltk_predictions_json = Column(Text, nullable=False)
    url_features_json = Column(Text, nullable=False)
    url_details_json = Column(Text, nullable=False)
    nltk_features_json = Column(Text, nullable=False)
    nltk_details_json = Column(Text, nullable=False)
    verdict_summary = Column(Text, nullable=False)
    owasp_report_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    """Create database tables if they don't exist and run migrations."""
    Base.metadata.create_all(bind=engine)

    try:
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(scan_records)"))
            columns = [row[1] for row in result]
            if "owasp_report_json" not in columns:
                conn.execute(text(
                    "ALTER TABLE scan_records ADD COLUMN owasp_report_json TEXT"
                ))
                conn.commit()
    except Exception:
        pass


def save_scan(result: dict) -> int:
    """Save a scan result to the database. Returns the record ID."""
    db = SessionLocal()
    try:
        record = ScanRecord(
            url=result["url"],
            verdict=result["verdict"]["verdict"],
            confidence=result["verdict"]["confidence"],
            scan_time=result["scan_time"],
            predictions_json=json.dumps(result["predictions"]),
            nltk_predictions_json=json.dumps(result["nltk_predictions"]),
            url_features_json=json.dumps(result["url_features"]),
            url_details_json=json.dumps(result["url_details"]),
            nltk_features_json=json.dumps(result["nltk_features"]),
            nltk_details_json=json.dumps(result["nltk_details"]),
            verdict_summary=result["verdict"]["summary"],
            owasp_report_json=json.dumps(result["owasp_report"]) if result.get("owasp_report") else None,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record.id
    finally:
        db.close()


def get_scan_by_id(scan_id: int):
    """Retrieve a scan record by ID. Returns None if not found."""
    db = SessionLocal()
    try:
        record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if record is None:
            return None
        return _record_to_dict(record)
    finally:
        db.close()


def get_all_scans(limit: int = 100, offset: int = 0) -> list:
    """Retrieve all scan records, most recent first."""
    db = SessionLocal()
    try:
        records = (
            db.query(ScanRecord)
            .order_by(ScanRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_record_to_summary(record) for record in records]
    finally:
        db.close()


def get_scan_count() -> int:
    """Get total number of scan records."""
    db = SessionLocal()
    try:
        return db.query(ScanRecord).count()
    finally:
        db.close()


def delete_scan(scan_id: int) -> bool:
    """Delete a scan record by ID. Returns True if deleted."""
    db = SessionLocal()
    try:
        record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if record is None:
            return False
        db.delete(record)
        db.commit()
        return True
    finally:
        db.close()


def clear_all_scans() -> int:
    """Delete all scan records. Returns number of deleted records."""
    db = SessionLocal()
    try:
        count = db.query(ScanRecord).count()
        db.query(ScanRecord).delete()
        db.commit()
        return count
    finally:
        db.close()


def search_scans(query: str, limit: int = 100, offset: int = 0) -> list:
    """Search scan records by URL."""
    db = SessionLocal()
    try:
        records = (
            db.query(ScanRecord)
            .filter(ScanRecord.url.ilike(f"%{query}%"))
            .order_by(ScanRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_record_to_summary(record) for record in records]
    finally:
        db.close()


def _record_to_dict(record: ScanRecord) -> dict:
    """Convert a database record to a result dict (matching scan endpoint format)."""
    result = {
        "id": record.id,
        "url": record.url,
        "verdict": {
            "verdict": record.verdict,
            "confidence": record.confidence,
            "summary": record.verdict_summary,
        },
        "scan_time": record.scan_time,
        "predictions": json.loads(record.predictions_json),
        "nltk_predictions": json.loads(record.nltk_predictions_json),
        "url_features": json.loads(record.url_features_json),
        "url_details": json.loads(record.url_details_json),
        "nltk_features": json.loads(record.nltk_features_json),
        "nltk_details": json.loads(record.nltk_details_json),
        "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    }

    if record.owasp_report_json:
        result["owasp_report"] = json.loads(record.owasp_report_json)

    return result


def _record_to_summary(record: ScanRecord) -> dict:
    """Convert a database record to a summary dict for list view."""
    summary = {
        "id": record.id,
        "url": record.url,
        "verdict": record.verdict,
        "confidence": record.confidence,
        "scan_time": record.scan_time,
        "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Include OWASP risk rating in summary for the history list
    if record.owasp_report_json:
        try:
            owasp = json.loads(record.owasp_report_json)
            summary["owasp_rating"] = owasp.get("risk_rating", "")
            summary["owasp_score"] = owasp.get("risk_score", 0)
        except Exception:
            summary["owasp_rating"] = ""
            summary["owasp_score"] = 0
    else:
        summary["owasp_rating"] = ""
        summary["owasp_score"] = 0

    return summary

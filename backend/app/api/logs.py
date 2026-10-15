"""Log ingestion and retrieval endpoints."""
import io
import logging
from typing import Optional

import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.logs import PaginatedLogs, LogResponse, UploadResponse
from app.services.log_service import ingest_dataframe, get_logs
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.get("", response_model=PaginatedLogs)
def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Retrieve security logs with pagination and optional filters."""
    total, items = get_logs(db, page=page, page_size=page_size,
                            event_type=event_type, severity=severity, source_ip=source_ip)
    return PaginatedLogs(
        total=total,
        page=page,
        page_size=page_size,
        items=[
            LogResponse(
                id=item.id,
                log_id=item.log_id,
                timestamp=item.timestamp.isoformat() if item.timestamp else None,
                source_ip=item.source_ip,
                destination_ip=item.destination_ip,
                event_type=item.event_type,
                severity=item.severity,
                failed_login_count=item.failed_login_count or 0,
                request_count=item.request_count or 0,
                port=item.port,
                affected_asset=item.affected_asset,
                label=item.label,
            )
            for item in items
        ],
    )


@router.post("/upload", response_model=UploadResponse)
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Upload and ingest a CSV file of security logs.
    Validates file type, size, and required columns before ingestion.
    """
    MAX_SIZE = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # Validate file type
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only CSV files are accepted.",
        )

    content = await file.read()

    # Validate file size
    if len(content) > MAX_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE_MB} MB.",
        )

    try:
        df = pd.read_csv(io.BytesIO(content), low_memory=False)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not parse CSV: {str(e)[:200]}",
        )

    if df.empty:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The uploaded CSV file is empty.",
        )

    # Require at least 'event_type' column
    if "event_type" not in df.columns:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"CSV must contain an 'event_type' column. Found: {list(df.columns)[:10]}",
        )

    imported, skipped, warnings = ingest_dataframe(db, df)

    return UploadResponse(
        message=f"Import complete. {imported} records imported, {skipped} skipped.",
        records_imported=imported,
        records_skipped=skipped,
        warnings=warnings[:20],  # limit warning list length
    )

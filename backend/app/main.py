"""
CyberSecurity Analytics Platform — FastAPI Application Entry Point

Endpoints:
- GET  /health                          Health check
- GET  /api/dashboard/summary           Dashboard statistics
- GET  /api/logs                        Retrieve logs (paginated, filtered)
- POST /api/logs/upload                 Upload CSV dataset
- POST /api/detect                      Run detection on submitted records
- GET  /api/alerts                      Retrieve detected alerts
- GET  /api/incidents                   Retrieve correlated incidents
- GET  /api/compliance                  Retrieve compliance mappings
- GET  /api/reports                     List generated reports
- POST /api/reports/generate            Generate a security report
- GET  /api/reports/{report_id}/download  Download report PDF
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database.connection import init_db
from app.database.mongo import ensure_indexes, get_mongo_stats
from app.ml.detector import get_detection_engine
from app.api import health, logs, detection, compliance, reports, dashboard
from app.api import mongo_analytics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    settings.ensure_directories()
    init_db()

    # MongoDB — connect and create indexes (non-fatal if unavailable)
    mongo_stats = get_mongo_stats()
    if mongo_stats.get("available"):
        ensure_indexes()
        cols = mongo_stats.get("collections", {})
        logger.info(
            "MongoDB ready — db=%s  logs=%s  alerts=%s  incidents=%s",
            mongo_stats.get("database"),
            cols.get("security_logs", 0),
            cols.get("alerts", 0),
            cols.get("incidents", 0),
        )
    else:
        logger.warning(
            "MongoDB unavailable at startup (%s). "
            "Platform runs on SQLite only — MongoDB writes are disabled.",
            mongo_stats.get("error", "connection failed"),
        )

    # Pre-load ML model
    engine = get_detection_engine()
    if engine.model_loaded:
        logger.info("ML model loaded at startup: %s", engine.model_name)
    else:
        logger.warning(
            "No trained model found. Run: python scripts/train_model.py"
        )
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "AI/ML-based cybersecurity log analysis platform. "
        "Detects suspicious activity, correlates alerts into incidents, "
        "maps findings to compliance frameworks, and generates reports."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router)
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(detection.router)
app.include_router(compliance.router)
app.include_router(reports.router)
app.include_router(mongo_analytics.router)


@app.get("/", include_in_schema=False)
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }

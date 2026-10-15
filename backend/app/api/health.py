"""Health check endpoint — shows SQLite and MongoDB status."""
from fastapi import APIRouter
from app.ml.detector import get_detection_engine
from app.database.mongo import get_mongo_stats

router = APIRouter()


@router.get("/health", tags=["Health"])
def health_check():
    engine      = get_detection_engine()
    mongo_stats = get_mongo_stats()

    return {
        "status":       "ok",
        "model_loaded": engine.model_loaded,
        "model_name":   engine.model_name,
        "sqlite":       "ok",
        "mongodb": {
            "available": mongo_stats.get("available", False),
            "database":  mongo_stats.get("database"),
            "collections": mongo_stats.get("collections", {}),
        },
    }

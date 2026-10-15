"""Application configuration using pydantic-settings."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import List


BASE_DIR = Path(__file__).resolve().parent.parent.parent  # project root


class Settings(BaseSettings):
    APP_NAME: str = "CyberSecurity Analytics Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///./cybersecurity.db"

    # MongoDB
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "cybersecurity_analytics"
    MONGODB_ENABLED: bool = True

    DATA_DIR: str = str(BASE_DIR / "data")
    MODELS_DIR: str = str(BASE_DIR / "models")
    REPORTS_DIR: str = str(BASE_DIR / "reports")
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    MAX_UPLOAD_SIZE_MB: int = 50

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
    }

    @property
    def raw_data_dir(self) -> Path:
        return Path(self.DATA_DIR) / "raw"

    @property
    def processed_data_dir(self) -> Path:
        return Path(self.DATA_DIR) / "processed"

    @property
    def synthetic_data_dir(self) -> Path:
        return Path(self.DATA_DIR) / "synthetic"

    @property
    def models_path(self) -> Path:
        return Path(self.MODELS_DIR)

    @property
    def reports_path(self) -> Path:
        return Path(self.REPORTS_DIR)

    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        for d in [
            self.raw_data_dir,
            self.processed_data_dir,
            self.synthetic_data_dir,
            self.models_path,
            self.reports_path,
        ]:
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()

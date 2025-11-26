from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    mongo_uri: str = Field(..., env="MONGO_URI")
    mongo_db_name: str = Field("netanel1161_db_user", env="MONGO_DB_NAME")
    chroma_persist_dir: str = Field("./chroma_db", env="CHROMA_PERSIST_DIR")

    flask_env: str = Field("production", env="FLASK_ENV")
    port: int = Field(8000, env="PORT")
    allowed_origins: List[str] = Field(default_factory=list, env="ALLOWED_ORIGINS")

    session_secret_key: str = Field(..., env="SESSION_SECRET_KEY")
    admin_default_user: Optional[str] = Field(None, env="ADMIN_DEFAULT_USER")
    admin_default_password: Optional[str] = Field(None, env="ADMIN_DEFAULT_PASSWORD")
    admin_default_role: str = Field("admin", env="ADMIN_DEFAULT_ROLE")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    # Handle comma-separated origins if provided as a single string
    if len(settings.allowed_origins) == 1 and "," in settings.allowed_origins[0]:
        settings.allowed_origins = [
            origin.strip() for origin in settings.allowed_origins[0].split(",") if origin.strip()
        ]
    return settings

from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import uuid

# Используем SQLite
SQLALCHEMY_DATABASE_URL = "sqlite:///./secure_storage.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class StorageNode(Base):
    __tablename__ = "storage_nodes"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, nullable=False)
    port = Column(String, nullable=False)
    access_key = Column(String, nullable=False)
    secret_key = Column(String, nullable=False)
    bucket_name = Column(String, default="data")
    is_active = Column(Boolean, default=True)

    def get_endpoint(self):
        protocol = "http" 
        return f"{protocol}://{self.ip}:{self.port}"

class Document(Base):
    __tablename__ = "documents"

    # ID теперь String (UUID)
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    content_type = Column(String)
    file_extension = Column(String)
    file_kind = Column(String)
    size = Column(Integer)
    created_at = Column(DateTime, default=datetime.now)
    last_modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    active_version = Column(Integer, default=1)
    
    shards = relationship("DocShard", back_populates="document", cascade="all, delete-orphan")

class DocShard(Base):
    __tablename__ = "doc_shards"

    id = Column(Integer, primary_key=True, index=True)
    # doc_id теперь ссылается на String
    doc_id = Column(String, ForeignKey("documents.id"))
    version = Column(Integer, nullable=False)
    shard_index = Column(Integer, nullable=False)
    node_id = Column(Integer, ForeignKey("storage_nodes.id"))
    object_key = Column(String, nullable=False)
    
    k_param = Column(Integer) 
    n_param = Column(Integer)
    meta_json = Column(String)

    document = relationship("Document", back_populates="shards")
    node = relationship("StorageNode")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

    user = relationship("User", back_populates="refresh_tokens")

def init_db():
    Base.metadata.create_all(bind=engine)
    _ensure_document_columns()

def _ensure_document_columns():
    with engine.connect() as connection:
        result = connection.execute(text("PRAGMA table_info(documents)"))
        existing_columns = {row[1] for row in result.fetchall()}

        if "file_extension" not in existing_columns:
            connection.execute(text("ALTER TABLE documents ADD COLUMN file_extension VARCHAR"))
        if "file_kind" not in existing_columns:
            connection.execute(text("ALTER TABLE documents ADD COLUMN file_kind VARCHAR"))

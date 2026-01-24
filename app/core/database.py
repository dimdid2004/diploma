from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean
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

def init_db():
    Base.metadata.create_all(bind=engine)
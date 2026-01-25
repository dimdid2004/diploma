from pathlib import Path
from typing import Optional

FILE_KIND_MAP = {
    "image": {"image/"},
    "pdf": {"application/pdf"},
    "text": {"text/"},
    "audio": {"audio/"},
    "video": {"video/"},
}

OFFICE_MIME_KINDS = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
    "application/msword": "document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "spreadsheet",
    "application/vnd.ms-excel": "spreadsheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "presentation",
    "application/vnd.ms-powerpoint": "presentation",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}


def detect_file_extension(filename: str) -> str:
    return Path(filename).suffix.lower().lstrip(".")


def detect_file_kind(filename: str, content_type: Optional[str]) -> str:
    extension = Path(filename).suffix.lower()
    if extension in ARCHIVE_EXTENSIONS:
        return "archive"

    if content_type:
        if content_type in OFFICE_MIME_KINDS:
            return OFFICE_MIME_KINDS[content_type]
        for kind, prefixes in FILE_KIND_MAP.items():
            for prefix in prefixes:
                if content_type.startswith(prefix):
                    return kind

    if extension in {".txt", ".md", ".json", ".csv", ".log"}:
        return "text"
    if extension in {".pdf"}:
        return "pdf"
    if extension in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}:
        return "image"
    if extension in {".mp3", ".wav", ".ogg", ".flac", ".m4a"}:
        return "audio"
    if extension in {".mp4", ".webm", ".mov", ".avi", ".mkv"}:
        return "video"
    if extension in {".doc", ".docx"}:
        return "document"
    if extension in {".xls", ".xlsx"}:
        return "spreadsheet"
    if extension in {".ppt", ".pptx"}:
        return "presentation"

    return "unknown"


def normalize_title(filename: str, title: Optional[str]) -> str:
    fallback = Path(filename).stem
    if not title:
        return fallback

    cleaned = title.strip()
    extension = Path(filename).suffix.lower()
    if extension and cleaned.lower().endswith(extension):
        cleaned = cleaned[: -len(extension)].rstrip()
    return cleaned or fallback

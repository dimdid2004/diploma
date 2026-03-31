class StorageServiceError(Exception):
    """Базовая ошибка сервиса хранения."""


class ShardsNotFoundError(StorageServiceError):
    """Для документа не найдено ни одного фрагмента."""


class NotEnoughShardsError(StorageServiceError):
    """Недостаточно доступных фрагментов для восстановления."""


class DataIntegrityError(StorageServiceError):
    """Фрагменты найдены, но целостность данных нарушена."""


class StorageNodeReadError(StorageServiceError):
    """Не удалось прочитать данные из удалённых хранилищ."""


class DocumentProcessingError(StorageServiceError):
    """Общая ошибка обработки документа."""
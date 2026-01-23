# Используем легкий образ Python
FROM python:3.9-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл зависимостей и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем остальной код
COPY . .

# Запускаем приложение через Uvicorn
# --host 0.0.0.0: слушаем все интерфейсы внутри контейнера
# --port 8000: стандартный порт FastAPI
# --reload: автоперезагрузка при изменении кода (удобно для разработки)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
# Обновляем версию до 3.10, чтобы убрать DeprecationWarning от boto3
FROM python:3.10-slim

WORKDIR /app

# Устанавливаем системные зависимости
# libssl-dev нужен для cryptography
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Создаем папки
RUN mkdir -p static templates

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
# Используем легкий образ Python
FROM python:3.9-slim

WORKDIR /app

# Установка git (иногда нужен для зависимостей) и libssl (для cryptography)
# gcc больше не нужен!
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Создаем папки для статики и шаблонов
RUN mkdir -p static templates

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
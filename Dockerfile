FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8000
ENV SECRET_KEY=changeme-in-production

EXPOSE 8000

CMD ["gunicorn", "wsgi:app", "--workers", "2", "--bind", "0.0.0.0:8000"]

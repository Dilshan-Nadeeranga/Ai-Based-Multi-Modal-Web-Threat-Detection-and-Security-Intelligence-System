FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
# The developer inspector (/inspector, /api/v1/dev/*) is never enabled in an image.
ENV APP_ENV=production

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
RUN pip install --no-deps .

EXPOSE 8002
CMD ["uvicorn", "c2_analyzer.api.main:app", "--host", "0.0.0.0", "--port", "8002"]

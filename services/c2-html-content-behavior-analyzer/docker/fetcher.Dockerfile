# Sandbox for collecting samples (scripts/collect.py), especially rendered mode,
# which runs the JavaScript of untrusted pages in Chromium.
#
# Build (from the service root):
#   docker build -f docker/fetcher.Dockerfile -t c2-fetcher .
# Run (only data/ is shared with the container):
#   docker run --rm --init --shm-size=1g --cap-drop=ALL --security-opt=no-new-privileges \
#     -v "${PWD}/data:/app/data" c2-fetcher fetch --mode rendered --limit 20

# Official image: Python + Chromium + all system libraries. Tag = playwright version.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    C2_IN_DOCKER=1

WORKDIR /app

COPY requirements-fetcher.txt .
RUN python3 -m pip install -r requirements-fetcher.txt

COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY scripts ./scripts
RUN python3 -m pip install --no-deps . \
    && mkdir -p /app/data && chown -R pwuser:pwuser /app/data

# Never run the browser as root: pwuser is the unprivileged user of the base image.
USER pwuser

ENTRYPOINT ["python3", "scripts/collect.py"]
CMD ["--help"]

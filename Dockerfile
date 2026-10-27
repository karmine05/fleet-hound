FROM python:3.11.13-slim-bookworm

WORKDIR /app

# Install dependencies first (for better caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --uid 10001 --create-home --home-dir /home/webviz --shell /sbin/nologin webviz

# Copy application code.
COPY webviz/ ./webviz/
# snapshot.diff API + enrich_worker import these from /app at runtime.
COPY src/ ./src/
COPY categorize_software.py ./categorize_software.py
COPY clear_db.py ./clear_db.py
COPY main.py ./main.py

# Config dir is mounted as a volume in docker-compose; pre-create + own it so
# the non-root user can write whitelist.json / audit.log without chmod gymnastics.
# Default known-publisher list for deployments that don't bind-mount config/
# (compose mounts ./config over /app/config, so the repo copy is what is used).
COPY config/known_publishers.json /app/config/known_publishers.json
COPY config/extension_threat_feeds.json /app/config/extension_threat_feeds.json
RUN mkdir -p /app/config /app/config/snapshots \
 && chown -R webviz:webviz /app

USER webviz

# Fail-closed default for prod image: refuse to start unless WEBVIZ_API_TOKEN
# is supplied (via env or *_FILE secret mount). Operators running this image
# must explicitly opt out by setting WEBVIZ_REQUIRE_AUTH=false in their
# compose/k8s spec — there is no silent-anonymous-read path in a production
# container. Dev (`python webviz/app.py` outside Docker) keeps the permissive
# default from the code path.
ENV WEBVIZ_REQUIRE_AUTH=true

EXPOSE 8080

# Health check — uses lightweight /api/health (database ping), not /api/graph (heavy query).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys, urllib.request; r = urllib.request.urlopen('http://localhost:8080/api/health', timeout=5); sys.exit(0 if r.status == 200 else 1)" || exit 1

# Gunicorn: bind 0.0.0.0 (container network). Two workers x 4 threads: a slow
# query no longer blocks a whole worker (and /api/health with it), and RAM is
# still left for the in-process OODA/enricher/extension threads. Timeout is
# 120s so a blast-radius query doesn't get killed mid-walk.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--worker-class", "gthread", \
     "--threads", "4", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--no-control-socket", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "webviz.app:app"]

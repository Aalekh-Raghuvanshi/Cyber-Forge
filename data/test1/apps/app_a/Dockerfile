FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DB_PATH=/tmp/benchmark.sqlite3
WORKDIR /srv/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
COPY app.py ./app.py
COPY data ./data
USER 10001:10001
EXPOSE 5000
CMD ["python", "app.py"]

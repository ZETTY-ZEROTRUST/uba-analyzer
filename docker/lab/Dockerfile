FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src:/app/vendor/log-pipeline/src OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
WORKDIR /app
COPY requirements-ml.lock requirements-lab.lock ./
RUN pip install --no-cache-dir --only-binary=:all: -r requirements-lab.lock
COPY src/zetty_uba ./src/zetty_uba
COPY vendor/log-pipeline ./vendor/log-pipeline
ENTRYPOINT ["python", "-m", "zetty_uba.lab"]

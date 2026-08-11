# Containerized deliberately-vulnerable demo API (for the Action / Testcontainers).
FROM python:3.12-slim
WORKDIR /demo
COPY app.py ./app.py
RUN pip install --no-cache-dir fastapi uvicorn
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

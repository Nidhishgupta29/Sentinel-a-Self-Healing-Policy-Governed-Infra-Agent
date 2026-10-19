FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY demo_app ./demo_app
COPY dashboard ./dashboard
COPY sentinel ./sentinel
COPY faults ./faults
COPY postmortems ./postmortems
COPY evals ./evals

EXPOSE 8000
CMD ["sh", "-c", "uvicorn dashboard.app:app --host 0.0.0.0 --port ${PORT:-8000}"]

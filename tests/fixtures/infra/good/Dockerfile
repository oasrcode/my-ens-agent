FROM python:3.12.4-slim@sha256:1111111111111111111111111111111111111111111111111111111111111111
RUN useradd --system --uid 10001 appuser
WORKDIR /app
COPY . /app
USER appuser
CMD ["python", "-m", "app"]

# Intentionally insecure fixture: unpinned base image, no non-root USER,
# hardcoded credential and a remote ADD without integrity verification.
FROM python:latest

ENV DB_PASSWORD=S3cr3t-Passw0rd-For-Demo

ADD https://example.com/tool.tar.gz /opt/tool.tar.gz

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000
CMD ["python", "-m", "auth_service"]

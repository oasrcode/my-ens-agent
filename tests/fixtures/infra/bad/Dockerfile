FROM python:latest
ENV DB_PASSWORD=supersecret123
ARG API_TOKEN=deadbeefcafe
ADD https://example.com/tool.tar.gz /opt/tool.tar.gz
RUN pip install -r requirements.txt
CMD ["python", "-m", "app"]

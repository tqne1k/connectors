FROM python:3.10-alpine

# Copy the connector
WORKDIR /opt/opencti-connector-import-file-stix

COPY . .
COPY ../apt ../
# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-import-file-stix && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# # Expose and entrypoint

# Start the connector
CMD ["python3", "main.py"]

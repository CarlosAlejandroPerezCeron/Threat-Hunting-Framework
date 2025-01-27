from elasticsearch import Elasticsearch
import structlog

# Conectar con Elasticsearch
es = Elasticsearch("http://localhost:9200")

def log_security_event(event_type, filename, result):
    log_entry = {
        "event_type": event_type,
        "filename": filename,
        "scan_result": result
    }
    es.index(index="threat-hunting-logs", body=log_entry)

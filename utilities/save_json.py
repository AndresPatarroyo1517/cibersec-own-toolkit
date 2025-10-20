import json
import csv
import logging

logger = logging.getLogger(__name__)

def save_json(results, path):
    """Guarda la lista de diccionarios results en un archivo JSON."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logger.info("Resultados guardados en JSON: %s", path)
    except Exception as e:
        logger.error("Error guardando JSON: %s", e)
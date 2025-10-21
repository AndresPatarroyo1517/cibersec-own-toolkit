import json
import csv
import os
from datetime import datetime, date
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
import logging

def _ensure_dir_for_file(path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

def _convert_values(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _convert_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_values(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_convert_values(v) for v in obj)
    return obj

def _write_json(payload: Any, path: str, logger: Optional[logging.Logger]=None) -> None:
    try:
        _ensure_dir_for_file(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        if logger:
            logger.info("JSON guardado en: %s", path)
    except Exception as e:
        if logger:
            logger.error("Error guardando JSON en %s: %s", path, e)
        else:
            raise

def _write_dicts_csv(dicts: List[Dict], path: str, logger: Optional[logging.Logger]=None) -> None:
    try:
        _ensure_dir_for_file(path)
        # union de keys
        fieldnames = set()
        for d in dicts:
            if isinstance(d, dict):
                fieldnames.update(d.keys())
        # preferir orden conocido si existe
        preferred = ["port", "state", "service", "version", "banner", "ip", "hostname"]
        ordered = [k for k in preferred if k in fieldnames] + sorted(fieldnames - set(preferred))
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=ordered, extrasaction="ignore")
            writer.writeheader()
            for d in dicts:
                # convertir None a "" para CSV
                row = {k: ("" if d.get(k) is None else d.get(k)) for k in ordered}
                writer.writerow(row)
        if logger:
            logger.info("CSV guardado en: %s", path)
    except Exception as e:
        if logger:
            logger.error("Error guardando CSV en %s: %s", path, e)
        else:
            raise

def _write_stats_csv(stats: Dict, path: str, logger: Optional[logging.Logger]=None) -> None:
    try:
        _ensure_dir_for_file(path)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["key", "value"])
            for k, v in stats.items():
                w.writerow([k, "" if v is None else v])
        if logger:
            logger.info("Stats CSV guardado en: %s", path)
    except Exception as e:
        if logger:
            logger.error("Error guardando stats CSV en %s: %s", path, e)
        else:
            raise

def save_results(
    results: Union[Dict, List[Dict]],
    output_format: str,
    base_path: str,
    stats: Dict,
    logger: Optional[logging.Logger] = None
) -> List[str]:
    created_files: List[str] = []

    try:
        safe_results = _convert_values(results)
        safe_stats = _convert_values(stats or {})

        if output_format in ("json", "both"):
            json_path = f"{base_path}.json"
            payload = {
                "metadata": {
                    "scan_time": datetime.now().isoformat(),
                },
                "results": safe_results,
                "statistics": safe_stats
            }
            _write_json(payload, json_path, logger)
            created_files.append(json_path)

        if output_format in ("csv", "both"):
            # Si results es dict y contiene 'ports' -> crear CSV de puertos
            if isinstance(safe_results, dict) and isinstance(safe_results.get("ports"), list):
                ports = safe_results.get("ports", [])
                ports_csv = f"{base_path}_ports.csv"
                if ports:
                    _write_dicts_csv(ports, ports_csv, logger)
                    created_files.append(ports_csv)
                else:
                    # crear archivo vacío con header si quieres, o solo guardar stats
                    with open(ports_csv, "w", newline="", encoding="utf-8") as f:
                        pass
                    if logger:
                        logger.warning("No se encontraron puertos para escribir en %s (archivo vacío creado)", ports_csv)
                    created_files.append(ports_csv)

            # Si results es lista -> escribir esa lista como CSV (hosts)
            elif isinstance(safe_results, list) and safe_results:
                hosts_csv = f"{base_path}_hosts.csv"
                _write_dicts_csv(safe_results, hosts_csv, logger)
                created_files.append(hosts_csv)
            elif isinstance(safe_results, list) and not safe_results:
                # crear archivo vacío
                hosts_csv = f"{base_path}_hosts.csv"
                with open(hosts_csv, "w", newline="", encoding="utf-8") as f:
                    pass
                if logger:
                    logger.warning("Lista de hosts vacía, creado %s (vacío)", hosts_csv)
                created_files.append(hosts_csv)

            # Siempre escribir stats CSV
            stats_csv = f"{base_path}_stats.csv"
            _write_stats_csv(safe_stats, stats_csv, logger)
            created_files.append(stats_csv)

    except Exception as e:
        if logger:
            logger.error("Error guardando resultados: %s", e)
        else:
            raise

    return created_files
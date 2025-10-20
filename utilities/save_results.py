import json
import csv
from typing import List, Dict, Optional, Set
import logging
from datetime import datetime

def save_results(results: List[Dict], output_format: str, base_path: str, 
                 stats: Dict, logger: logging.Logger):
    """
    Guarda resultados en el formato especificado.
    
    Args:
        results: Lista de hosts descubiertos
        output_format: 'json', 'csv', o 'both'
        base_path: Path base sin extensión
        stats: Estadísticas del escaneo
        logger: Logger para mensajes
    """
    import json
    import csv
    
    # JSON
    if output_format in ('json', 'both'):
        json_path = f"{base_path}.json"
        output_data = {
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'statistics': stats
            },
            'hosts': results
        }
        
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON guardado en: {json_path}")
        except Exception as e:
            logger.error(f"Error guardando JSON: {e}")
    
    # CSV
    if output_format in ('csv', 'both'):
        csv_path = f"{base_path}.csv"
        
        if not results:
            logger.warning("No hay resultados para guardar en CSV")
            return
        
        try:
            # Determinar columnas dinámicamente
            fieldnames = list(results[0].keys())
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            
            logger.info(f"CSV guardado en: {csv_path}")
        except Exception as e:
            logger.error(f"Error guardando CSV: {e}")
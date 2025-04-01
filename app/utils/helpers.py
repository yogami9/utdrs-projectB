import pandas as pd
import numpy as np
import re
from typing import Dict, List, Union, Any
import logging

logger = logging.getLogger(__name__)

def validate_csv_format(df: pd.DataFrame, data_type: str) -> bool:
    """
    Validates if the CSV has the correct format for the specified data type
    
    Args:
        df: Pandas DataFrame to validate
        data_type: Type of data (network, endpoint, authentication, etc.)
        
    Returns:
        bool: True if valid, False otherwise
    """
    required_columns = {
        'network': ['timestamp', 'source_ip', 'destination_ip', 'protocol', 'packet_size'],
        'endpoint': ['timestamp', 'event_id', 'event_type', 'user'],
        'authentication': ['timestamp', 'user_id', 'login_status'],
        'email': ['timestamp', 'sender', 'receiver', 'subject'],
        'threat_intelligence': ['timestamp', 'ip_address', 'domain']
    }
    
    if data_type not in required_columns:
        logger.warning(f"Unknown data type for validation: {data_type}")
        return False
        
    for col in required_columns[data_type]:
        if col not in df.columns:
            logger.warning(f"Required column {col} missing for {data_type} data")
            return False
            
    return True

def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip):
        return False
        
    # Check each octet
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)

def is_valid_email(email: str) -> bool:
    """
    Check if a string is a valid email address
    
    Args:
        email: Email address to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def format_detection_results(anomalies: pd.DataFrame, known_threats: pd.DataFrame) -> Dict[str, Any]:
    """
    Format detection results for API response
    
    Args:
        anomalies: DataFrame with detected anomalies
        known_threats: DataFrame with detected known threats
        
    Returns:
        Dict: Formatted results
    """
    results = {
        "total_anomalies": len(anomalies),
        "total_known_threats": len(known_threats),
        "anomalies": anomalies.to_dict(orient='records') if not anomalies.empty else [],
        "known_threats": known_threats.to_dict(orient='records') if not known_threats.empty else [],
        "summary": {
            "risk_level": "low" if len(anomalies) == 0 and len(known_threats) == 0 else "medium" if len(anomalies) + len(known_threats) < 5 else "high"
        }
    }
    
    return results

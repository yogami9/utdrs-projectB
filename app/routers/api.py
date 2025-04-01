from fastapi import APIRouter, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse
import pandas as pd
import os
import tempfile
from app.models.detection import ThreatDetectionSystem
from typing import Optional
import json

router = APIRouter(
    prefix="/api",
    tags=["threat-detection"],
    responses={404: {"description": "Not found"}},
)

# Initialize the threat detection system
detection_system = ThreatDetectionSystem()

@router.post("/analyze")
async def analyze_data(
    file: UploadFile = File(...),
    data_type: str = Form(...),
):
    """
    Analyze data for threats
    
    Args:
        file: CSV file containing data to analyze
        data_type: Type of data (network, endpoint, authentication, email, threat_intelligence)
    
    Returns:
        Detected anomalies and known threats
    """
    # Validate data type
    valid_data_types = ["network", "endpoint", "authentication", "email", "threat_intelligence"]
    if data_type not in valid_data_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid data type. Must be one of: {', '.join(valid_data_types)}"
        )
    
    # Save uploaded file temporarily
    try:
        # Create a temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
        temp_file_path = temp_file.name
        
        # Write content to the file
        content = await file.read()
        with open(temp_file_path, 'wb') as f:
            f.write(content)
        
        # Analyze the data
        anomalies, known_threats = detection_system.analyze(temp_file_path, data_type)
        
        # Convert results to JSON
        anomalies_json = anomalies.to_dict(orient='records') if not anomalies.empty else []
        known_threats_json = known_threats.to_dict(orient='records') if not known_threats.empty else []
        
        # Remove temporary file
        os.unlink(temp_file_path)
        
        return {
            "anomalies": anomalies_json,
            "known_threats": known_threats_json,
            "total_anomalies": len(anomalies_json),
            "total_known_threats": len(known_threats_json)
        }
        
    except Exception as e:
        # Make sure to remove the temp file if there's an error
        if 'temp_file_path' in locals():
            try:
                os.unlink(temp_file_path)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Error analyzing data: {str(e)}")

@router.get("/sample-data/{data_type}")
async def get_sample_data(data_type: str):
    """
    Get sample data for a specific data type
    
    Args:
        data_type: Type of data (network, endpoint, authentication, email, threat_intelligence)
    
    Returns:
        Sample data in JSON format
    """
    valid_data_types = ["network", "endpoint", "authentication", "email", "threat_intelligence"]
    if data_type not in valid_data_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid data type. Must be one of: {', '.join(valid_data_types)}"
        )
    
    sample_file_path = f"data/sample_{data_type}_data.csv"
    
    try:
        if os.path.exists(sample_file_path):
            data = pd.read_csv(sample_file_path)
            return data.to_dict(orient='records')
        else:
            raise HTTPException(status_code=404, detail=f"Sample data for {data_type} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving sample data: {str(e)}")

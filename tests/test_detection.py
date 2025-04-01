import pytest
import pandas as pd
import numpy as np
from app.models.detection import ThreatDetectionSystem
import os
import tempfile

@pytest.fixture
def sample_network_data():
    """Create sample network data for testing"""
    data = {
        'timestamp': ['2025-04-01T12:00:00', '2025-04-01T12:01:00', '2025-04-01T12:02:00'],
        'source_ip': ['192.168.1.100', '192.168.1.101', '192.168.1.102'],
        'destination_ip': ['192.168.1.200', '192.168.1.200', '192.168.1.200'],
        'source_port': [443, 443, 443],
        'destination_port': [80, 80, 80],
        'protocol': ['TCP', 'TCP', 'TCP'],
        'packet_size': [1500, 1400, 5000],  # The last one is anomalous
        'ttl': [64, 64, 50],
        'flags': ['SYN', 'ACK', 'SYN'],
        'bandwidth_usage': ['high', 'medium', 'high']
    }
    return pd.DataFrame(data)

@pytest.fixture
def detection_system():
    """Create a detection system instance for testing"""
    return ThreatDetectionSystem()

def test_process_network_data(detection_system, sample_network_data):
    """Test processing of network data"""
    processed_data = detection_system.process_network_data(sample_network_data)
    
    # Check that traffic_volume is calculated correctly
    assert 'traffic_volume' in processed_data.columns
    assert processed_data.shape[0] == 3
    
    # Check that original columns are preserved
    expected_columns = ['source_ip', 'destination_ip', 'protocol', 'packet_size', 
                        'ttl', 'flags', 'bandwidth_usage', 'traffic_volume']
    for col in expected_columns:
        assert col in processed_data.columns

def test_anomaly_detection(detection_system, sample_network_data):
    """Test anomaly detection with isolation forest"""
    # Process data
    processed_data = detection_system.process_network_data(sample_network_data)
    
    # Train the model
    detection_system.train_anomaly_detection_model(processed_data)
    
    # Detect anomalies
    anomalies = detection_system.detect_anomalies(processed_data)
    
    # Check that anomalies are detected (the large packet)
    assert not anomalies.empty
    assert anomalies['packet_size'].iloc[0] == 5000

def test_analyze_workflow(detection_system):
    """Test the entire analysis workflow with a temporary file"""
    # Create a temporary CSV file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        # Write sample data
        tmp.write("timestamp,source_ip,destination_ip,source_port,destination_port,protocol,packet_size,ttl,flags,bandwidth_usage\n")
        tmp.write("2025-04-01T12:00:00,192.168.1.100,192.168.1.200,443,80,TCP,1500,64,SYN,high\n")
        tmp.write("2025-04-01T12:01:00,192.168.1.101,192.168.1.200,443,80,TCP,1400,64,ACK,medium\n")
        tmp.write("2025-04-01T12:02:00,192.168.1.102,192.168.1.200,443,80,TCP,5000,50,SYN,high\n")
        tmp_path = tmp.name
    
    try:
        # Run the analysis
        anomalies, known_threats = detection_system.analyze(tmp_path, 'network')
        
        # Check results
        assert not anomalies.empty
        assert 'anomaly_score' in anomalies.columns
        assert anomalies['packet_size'].iloc[0] == 5000
    finally:
        # Clean up
        os.unlink(tmp_path)

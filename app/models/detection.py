import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatDetectionSystem:
    def __init__(self):
        self.isolation_forest = IsolationForest(n_estimators=100, contamination=0.1)
        self.kmeans = KMeans(n_clusters=3)
        self.scaler = StandardScaler()
        logger.info("Initialized ThreatDetectionSystem")

    def load_data(self, file_path, data_type):
        """
        Loads the data based on the file path and the data type (Network, Endpoint, etc.)
        :param file_path: Path to the dataset (CSV).
        :param data_type: Type of data (e.g., 'network', 'endpoint', 'authentication', 'email', 'threat_intelligence')
        :return: pandas DataFrame
        """
        logger.info(f"Loading {data_type} data from {file_path}")
        data = pd.read_csv(file_path)

        if data_type == 'network':
            return self.process_network_data(data)
        elif data_type == 'endpoint':
            return self.process_endpoint_data(data)
        elif data_type == 'authentication':
            return self.process_authentication_data(data)
        elif data_type == 'email':
            return self.process_email_data(data)
        elif data_type == 'threat_intelligence':
            return self.process_threat_intelligence_data(data)
        else:
            logger.error(f"Unknown data type: {data_type}")
            raise ValueError(f"Unknown data type: {data_type}")

    def process_network_data(self, data):
        """
        Processes network traffic data for threat detection.
        :param data: Raw network data
        :return: Processed DataFrame
        """
        data['timestamp'] = pd.to_datetime(data['timestamp'])
        # Calculate traffic volume by source IP
        data['traffic_volume'] = data.groupby('source_ip')['packet_size'].transform('sum')
        features = ['source_ip', 'destination_ip', 'protocol', 'packet_size', 'ttl', 'flags', 'bandwidth_usage', 'traffic_volume']
        return data[features]

    def process_endpoint_data(self, data):
        """
        Processes endpoint behavior data (e.g., file modifications, process monitoring).
        :param data: Raw endpoint data
        :return: Processed DataFrame
        """
        data['timestamp'] = pd.to_datetime(data['timestamp'])
        data['cpu_usage'] = pd.to_numeric(data['cpu_usage'].str.replace('%', ''))
        data['memory_usage'] = pd.to_numeric(data['memory_usage'].str.replace('MB', ''))
        return data[['timestamp', 'user', 'process_name', 'cpu_usage', 'memory_usage']]

    def process_authentication_data(self, data):
        """
        Processes authentication logs data.
        :param data: Raw authentication data
        :return: Processed DataFrame
        """
        data['timestamp'] = pd.to_datetime(data['timestamp'])
        return data[['timestamp', 'user_id', 'login_status', 'geolocation', 'auth_method']]

    def process_email_data(self, data):
        """
        Processes email data for phishing detection.
        :param data: Raw email data
        :return: Processed DataFrame
        """
        return data[['timestamp', 'sender', 'receiver', 'subject', 'links_in_email', 'file_type']]

    def process_threat_intelligence_data(self, data):
        """
        Processes threat intelligence data such as IoCs and malware signatures.
        :param data: Raw threat intelligence data
        :return: Processed DataFrame
        """
        return data[['timestamp', 'ip_address', 'domain', 'signature_id', 'hash', 'url', 'email_pattern']]

    def train_anomaly_detection_model(self, data):
        """
        Trains an anomaly detection model (Isolation Forest) to detect anomalies in the data.
        :param data: Processed data for anomaly detection.
        """
        # Scale numerical features for better performance
        logger.info("Training anomaly detection model")
        numeric_data = data.select_dtypes(include=[np.number])
        if len(numeric_data.columns) == 0:
            logger.warning("No numerical columns found for anomaly detection")
            return
            
        scaled_data = self.scaler.fit_transform(numeric_data)
        # Fit the model
        self.isolation_forest.fit(scaled_data)
        logger.info("Anomaly detection model trained successfully")

    def detect_anomalies(self, data):
        """
        Detects anomalies in the data using the trained Isolation Forest model.
        :param data: Processed data for anomaly detection.
        :return: Data with anomaly scores
        """
        logger.info("Detecting anomalies")
        numeric_data = data.select_dtypes(include=[np.number])
        if len(numeric_data.columns) == 0:
            logger.warning("No numerical columns found for anomaly detection")
            return pd.DataFrame()
            
        scaled_data = self.scaler.transform(numeric_data)
        # Predict anomalies (-1 indicates anomaly, 1 indicates normal)
        anomalies = self.isolation_forest.predict(scaled_data)
        data['anomaly_score'] = anomalies
        anomalies_df = data[data['anomaly_score'] == -1]
        logger.info(f"Detected {len(anomalies_df)} anomalies")
        return anomalies_df

    def detect_known_threats(self, data, data_type):
        """
        Detects known threats using pattern matching or rules.
        :param data: Data to check for known threats.
        :param data_type: Type of data to analyze
        :return: Data with identified known threats
        """
        logger.info(f"Detecting known threats in {data_type} data")
        threats = []

        if data_type == 'email':
            # Check for phishing links in email content
            if 'links_in_email' in data.columns:
                phishing_links = data[data['links_in_email'].str.contains("maliciouslink|phishinglink", na=False)]
                threats.append(phishing_links)
                logger.info(f"Detected {len(phishing_links)} phishing links")

        elif data_type == 'threat_intelligence':
            # Check for known malware in network traffic or emails (example: malware hashes)
            if 'hash' in data.columns:
                known_malware = data[data['hash'].str.contains('malware_hash_pattern', na=False)]
                threats.append(known_malware)
                logger.info(f"Detected {len(known_malware)} known malware instances")

        elif data_type == 'authentication':
            # Check for unauthorized login attempts in authentication data
            if 'login_status' in data.columns:
                brute_force_attempts = data[data['login_status'] == 'failed']
                threats.append(brute_force_attempts)
                logger.info(f"Detected {len(brute_force_attempts)} failed login attempts")

        if not threats:
            return pd.DataFrame()
            
        return pd.concat(threats).drop_duplicates()

    def analyze(self, file_path, data_type):
        """
        Main function to analyze and detect threats in the provided data.
        :param file_path: Path to the dataset (CSV).
        :param data_type: Type of data to analyze (e.g., 'network', 'endpoint', 'authentication', 'email', 'threat_intelligence')
        :return: DataFrame with detected threats
        """
        logger.info(f"Starting analysis of {data_type} data from {file_path}")
        
        try:
            # Load and preprocess the data
            data = self.load_data(file_path, data_type)
            
            # Train anomaly detection model if necessary
            self.train_anomaly_detection_model(data)
            
            # Detect anomalies in the data
            anomalies = self.detect_anomalies(data)
            
            # Detect known threats
            known_threats = self.detect_known_threats(data, data_type)
            
            logger.info(f"Analysis completed for {data_type} data")
            return anomalies, known_threats
        except Exception as e:
            logger.error(f"Error analyzing {data_type} data: {str(e)}")
            raise

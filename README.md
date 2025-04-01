# Unified Threat Detection and Response System (UTDRS)

A comprehensive system for detecting and responding to cybersecurity threats using machine learning and data analysis.

## Overview

The UTDRS is designed to ingest various types of security data and identify both known threats and anomalous behavior that could indicate new or unknown attacks. It integrates multiple detection techniques into a unified system, providing a comprehensive view of your security posture.

## Features

- **Network Intrusion Detection**: Analyze network traffic for suspicious patterns
- **Endpoint Behavior Monitoring**: Detect unusual behavior on endpoints
- **Authentication Analysis**: Identify unauthorized access attempts
- **Email & Phishing Detection**: Spot malicious emails and attachments
- **Threat Intelligence Integration**: Utilize known threat indicators
- **Anomalous Behavior Detection**: Find insider threats and unusual activity
- **Interactive Dashboard**: Visualize and explore detected threats

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Git
- Python 3.9+

### Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/utdrs-project.git
   cd utdrs-project
   ```

2. Start the services using Docker Compose:
   ```bash
   docker-compose up -d
   ```

3. Access the API at http://localhost:8000

4. Access the API documentation at http://localhost:8000/docs

5. Access the dashboard at http://localhost:8000/dashboard

### Running the Dashboard Locally

You can also run the dashboard locally without Docker:

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the dashboard:
   ```bash
   python dashboard.py
   ```

3. The dashboard will automatically open in your default web browser

## Dashboard Usage

The UTDRS Dashboard provides an interactive interface to:

1. Upload and analyze security data files
2. Load sample data for testing and demonstration
3. View detected anomalies and known threats
4. Visualize the distribution of security issues
5. Track the overall risk level of your system

### Dashboard Screenshots

![Dashboard Main View](docs/images/dashboard-main.png)
![Dashboard Analysis Results](docs/images/dashboard-results.png)

## API Usage

### Analyze Data for Threats

```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@path/to/your/data.csv" \
  -F "data_type=network"
```

### Get Sample Data

```bash
curl -X GET "http://localhost:8000/api/sample-data/network" \
  -H "accept: application/json"
```

## Data Types

The system supports the following data types:

- **network**: Network traffic data
- **endpoint**: Endpoint behavior logs
- **authentication**: User authentication logs
- **email**: Email & phishing data
- **threat_intelligence**: Threat intelligence data

## Deployment

This project is configured for easy deployment on Render:

1. Push your code to GitHub
2. Connect your Render account to your GitHub repository
3. Create a new Web Service and select "Docker" as the environment
4. Set the appropriate environment variables
5. Deploy!

## Project Structure

```
utdrs-project/
├── data/
│   └── sample_*.csv files
├── tests/
│   └── test_detection.py
├── dashboard.py              # Dashboard runner script
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── render.yaml
└── README.md app/
│   ├── models/
│   │   └── detection.py
│   ├── routers/
│   │   └── api.py
│   ├── static/                  # Dashboard files
│   │   ├── css/
│   │   │   └── dashboard.css
│   │   ├── js/
│   │   │   └── dashboard.js
│   │   └── index.html
│   ├── utils/
│   │   └── helpers.py
│   └── main.py
├──
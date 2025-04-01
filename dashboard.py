#!/usr/bin/env python3
"""
Dashboard Runner for the Unified Threat Detection and Response System (UTDRS)
This script launches the FastAPI application with the dashboard enabled
"""

import os
import sys
import webbrowser
from pathlib import Path
import subprocess
import time
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def ensure_static_directory():
    """Ensure the static directory structure exists"""
    base_dir = Path("app/static")
    css_dir = base_dir / "css"
    js_dir = base_dir / "js"
    
    # Create directories if they don't exist
    for directory in [base_dir, css_dir, js_dir]:
        directory.mkdir(exist_ok=True, parents=True)
    
    logger.info("Static directory structure verified")

def create_static_files():
    """Check if static files exist and create them if needed"""
    # File paths
    html_file = Path("app/static/index.html")
    css_file = Path("app/static/css/dashboard.css")
    js_file = Path("app/static/js/dashboard.js")
    
    # Create the static files if they don't exist
    if not all([html_file.exists(), css_file.exists(), js_file.exists()]):
        logger.info("Creating static dashboard files...")
        
        # Note: In a real implementation, these should be proper file contents
        # For now, we'll just create placeholder files with messages to replace them
        
        # Create HTML file
        if not html_file.exists():
            with open(html_file, 'w') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UTDRS Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-warning">
            <h4>Dashboard Files Need to be Updated</h4>
            <p>Please replace the default dashboard files with the actual implementation files from the project repository.</p>
        </div>
    </div>
</body>
</html>""")
        
        # Create CSS file
        if not css_file.exists():
            with open(css_file, 'w') as f:
                f.write("/* Dashboard CSS file */")
        
        # Create JS file
        if not js_file.exists():
            with open(js_file, 'w') as f:
                f.write("// Dashboard JavaScript file")
        
        logger.info("Dashboard placeholder files created")

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import pandas
        import numpy
        import sklearn
        logger.info("All required dependencies are installed")
        return True
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        logger.info("Please install dependencies using: pip install -r requirements.txt")
        return False

def start_server(port=8000, open_browser=True):
    """Start the FastAPI server"""
    server_url = f"http://localhost:{port}"
    dashboard_url = f"{server_url}/dashboard"
    
    logger.info(f"Starting UTDRS server on {server_url}")
    
    # Open browser tab to the dashboard
    if open_browser:
        logger.info(f"Opening dashboard in browser: {dashboard_url}")
        webbrowser.open(dashboard_url)
    
    # Start the server
    subprocess.run(["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", str(port), "--reload"])

def main():
    """Main function to run the dashboard"""
    parser = argparse.ArgumentParser(description="Run the UTDRS Dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()
    
    # Ensure we're in the project root directory
    if not os.path.exists("app") or not os.path.exists("requirements.txt"):
        logger.error("Please run this script from the project root directory")
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Ensure static directory exists
    ensure_static_directory()
    
    # Create static files if needed
    create_static_files()
    
    # Start the server
    start_server(port=args.port, open_browser=not args.no_browser)

if __name__ == "__main__":
    main()
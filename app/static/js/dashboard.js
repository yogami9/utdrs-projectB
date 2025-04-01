document.addEventListener('DOMContentLoaded', function() {
    // Global variables
    const apiBaseUrl = '/api';
    let threatsChart = null;
    
    // DOM elements
    const analyzeForm = document.getElementById('analyzeForm');
    const loadSampleBtn = document.getElementById('loadSampleData');
    const resultsSection = document.getElementById('resultsSection');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const errorMessage = document.getElementById('errorMessage');
    const anomalyCount = document.getElementById('anomalyCount');
    const threatCount = document.getElementById('threatCount');
    const riskLevelBadge = document.getElementById('riskLevelBadge');
    const noAnomaliesMessage = document.getElementById('noAnomaliesMessage');
    const noThreatsMessage = document.getElementById('noThreatsMessage');
    const rawJson = document.getElementById('rawJson');
    
    // Table elements
    const anomaliesTableHeader = document.getElementById('anomaliesTableHeader');
    const anomaliesTableBody = document.getElementById('anomaliesTableBody');
    const threatsTableHeader = document.getElementById('threatsTableHeader');
    const threatsTableBody = document.getElementById('threatsTableBody');
    
    // Form submission handler
    analyzeForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(analyzeForm);
        
        // Show loading spinner and hide other sections
        loadingSpinner.style.display = 'block';
        resultsSection.style.display = 'none';
        errorMessage.style.display = 'none';
        
        // Send data to API
        fetch(`${apiBaseUrl}/analyze`, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.detail || 'Error analyzing data');
                });
            }
            return response.json();
        })
        .then(data => {
            displayResults(data);
        })
        .catch(error => {
            // Show error message
            errorMessage.textContent = error.message;
            errorMessage.style.display = 'block';
            loadingSpinner.style.display = 'none';
        });
    });
    
    // Load sample data button handler
    loadSampleBtn.addEventListener('click', function() {
        const dataType = document.getElementById('dataType').value;
        
        // Show loading spinner and hide other sections
        loadingSpinner.style.display = 'block';
        resultsSection.style.display = 'none';
        errorMessage.style.display = 'none';
        
        // Fetch sample data
        fetch(`${apiBaseUrl}/sample-data/${dataType}`)
        .then(response => {
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.detail || 'Error loading sample data');
                });
            }
            return response.json();
        })
        .then(data => {
            // Mock result structure based on sample data
            const mockResult = {
                anomalies: data.filter((item, index) => index % 3 === 0), // Every 3rd item as anomaly for demo
                known_threats: data.filter((item, index) => index % 5 === 0), // Every 5th item as threat for demo
                total_anomalies: Math.floor(data.length / 3),
                total_known_threats: Math.floor(data.length / 5)
            };
            
            displayResults(mockResult);
        })
        .catch(error => {
            // Show error message
            errorMessage.textContent = error.message;
            errorMessage.style.display = 'block';
            loadingSpinner.style.display = 'none';
        });
    });
    
    // Function to display results
    function displayResults(data) {
        // Hide loading spinner and show results
        loadingSpinner.style.display = 'none';
        resultsSection.style.display = 'block';
        
        // Update metrics
        anomalyCount.textContent = data.total_anomalies;
        threatCount.textContent = data.total_known_threats;
        
        // Set risk level badge
        const riskLevel = calculateRiskLevel(data.total_anomalies, data.total_known_threats);
        riskLevelBadge.textContent = `Risk Level: ${riskLevel.toUpperCase()}`;
        riskLevelBadge.classList.remove('low', 'medium', 'high');
        riskLevelBadge.classList.add(riskLevel);
        
        // Show raw JSON data
        rawJson.textContent = JSON.stringify(data, null, 2);
        
        // Create or update chart
        updateChart(data.total_anomalies, data.total_known_threats);
        
        // Populate tables
        populateAnomaliesTable(data.anomalies);
        populateThreatsTable(data.known_threats);
    }
    
    // Function to calculate risk level
    function calculateRiskLevel(anomalies, threats) {
        const total = anomalies + threats;
        if (total === 0) return 'low';
        if (total < 5) return 'medium';
        return 'high';
    }
    
    // Function to update or create chart
    function updateChart(anomalies, threats) {
        const chartCanvas = document.getElementById('threatsChart');
        
        // Destroy existing chart if exists
        if (threatsChart) {
            threatsChart.destroy();
        }
        
        // Create new chart
        threatsChart = new Chart(chartCanvas, {
            type: 'bar',
            data: {
                labels: ['Anomalies', 'Known Threats'],
                datasets: [{
                    label: 'Detected Issues',
                    data: [anomalies, threats],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.6)',
                        'rgba(255, 206, 86, 0.6)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(255, 206, 86, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
    
    // Function to populate anomalies table
    function populateAnomaliesTable(anomalies) {
        // Clear previous content
        anomaliesTableHeader.innerHTML = '';
        anomaliesTableBody.innerHTML = '';
        
        // Show/hide no anomalies message
        if (anomalies.length === 0) {
            noAnomaliesMessage.style.display = 'block';
            return;
        } else {
            noAnomaliesMessage.style.display = 'none';
        }
        
        // Get column headers from first anomaly
        const firstAnomaly = anomalies[0];
        const headers = Object.keys(firstAnomaly);
        
        // Create header row
        headers.forEach(header => {
            const th = document.createElement('th');
            th.textContent = formatColumnName(header);
            anomaliesTableHeader.appendChild(th);
        });
        
        // Create rows for each anomaly
        anomalies.forEach(anomaly => {
            const tr = document.createElement('tr');
            
            headers.forEach(header => {
                const td = document.createElement('td');
                td.textContent = anomaly[header] !== undefined ? anomaly[header] : '';
                tr.appendChild(td);
            });
            
            anomaliesTableBody.appendChild(tr);
        });
    }
    
    // Function to populate threats table
    function populateThreatsTable(threats) {
        // Clear previous content
        threatsTableHeader.innerHTML = '';
        threatsTableBody.innerHTML = '';
        
        // Show/hide no threats message
        if (threats.length === 0) {
            noThreatsMessage.style.display = 'block';
            return;
        } else {
            noThreatsMessage.style.display = 'none';
        }
        
        // Get column headers from first threat
        const firstThreat = threats[0];
        const headers = Object.keys(firstThreat);
        
        // Create header row
        headers.forEach(header => {
            const th = document.createElement('th');
            th.textContent = formatColumnName(header);
            threatsTableHeader.appendChild(th);
        });
        
        // Create rows for each threat
        threats.forEach(threat => {
            const tr = document.createElement('tr');
            
            headers.forEach(header => {
                const td = document.createElement('td');
                td.textContent = threat[header] !== undefined ? threat[header] : '';
                tr.appendChild(td);
            });
            
            threatsTableBody.appendChild(tr);
        });
    }
    
    // Format column name for display (camelCase to Title Case)
    function formatColumnName(column) {
        return column
            .replace(/([A-Z])/g, ' $1') // Add space before capital letters
            .replace(/_/g, ' ') // Replace underscores with spaces
            .replace(/^./, str => str.toUpperCase()); // Capitalize first letter
    }
});
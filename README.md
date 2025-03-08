# AI-Powered Threat Detection System

A comprehensive threat detection system that analyzes network data from multiple sources to identify and mitigate potential security threats.

## Overview

This system leverages machine learning to analyze RIPE Atlas traceroute data and BGP/RPKI feeds to detect network anomalies and potential routing attacks. It provides automated threat assessment, alerting, and suggested mitigation strategies.

## Key Features

- **Atlas Traceroute Analysis**: Detects anomalies in network paths using machine learning
- **BGP/RPKI Validation**: Identifies invalid or suspicious BGP route announcements
- **Hijack Detection**: Uses machine learning to predict potential BGP hijacking attempts
- **Integrated Threat Assessment**: Combines multiple data sources for comprehensive security analysis
- **Automated Alerting**: Provides email notifications and API integration for critical threats
- **Mitigation Suggestions**: Recommends actions based on detected threats

## Requirements

- Python 3.7+
- Required packages:
  - pandas
  - numpy
  - scikit-learn
  - requests
  - logging

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ai-threat-detection.git
   cd ai-threat-detection
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Create a configuration file (`config.json`):
   ```json
   {
     "atlas_api_key": "your_atlas_api_key_here",
     "bgp_api_key": "your_bgp_api_key_here",
     "email_config": {
       "default_recipients": ["security-team@example.com"],
       "smtp_server": "smtp.example.com",
       "smtp_port": 587,
       "smtp_user": "alerts@example.com",
       "smtp_password": "your_password_here"
     },
     "api_config": {
       "notification_endpoints": [
         "https://api.example.com/security-notifications"
       ]
     }
   }
   ```

## Usage

### Basic Usage

```python
from threat_detection import ThreatDetectionSystem

# Initialize with configuration
system = ThreatDetectionSystem(config)
system.initialize()

# Run a detection cycle
results = system.run_detection_cycle()

# Generate a report
report = system.generate_report(results)
print(report)
```

### Command Line Interface

The system provides a convenient command-line interface:

```
python threat_detection.py --config config.json --mode full --output report.txt
```

Command-line options:
- `--config`: Path to configuration file (default: config.json)
- `--mode`: Operation mode (initialize, detect, report, or full)
- `--alert-threshold`: Threshold for generating alerts (0-100)
- `--output`: Output file for report
- `--verbose`: Enable verbose logging

## System Components

### AtlasDataAnalyzer

Analyzes RIPE Atlas traceroute data to detect network path anomalies:
- Fetches traceroute data from the RIPE Atlas API
- Extracts features such as RTT, hop count, and IP changes
- Uses Isolation Forest for anomaly detection

### BGPRPKIValidator

Validates BGP routes against RPKI data and detects potential hijacks:
- Fetches BGP data from Route Views or similar sources
- Validates routes against ROA data
- Uses Random Forest for hijack prediction

### ThreatPredictor

Integrates multiple data sources to assess overall threat levels:
- Combines traceroute anomalies and BGP hijack predictions
- Calculates normalized threat scores
- Classifies threats into Low, Medium, High, and Critical levels

### AlertSystem

Manages alerts and mitigation suggestions:
- Generates alerts based on threat assessments
- Sends email notifications to security teams
- Provides API integration for automated response
- Suggests mitigation strategies based on threat types

## Customization

The system is designed to be modular and extensible. You can:

1. Add new data sources by creating additional analyzer components
2. Modify the feature extraction logic for specific use cases
3. Customize the machine learning models and parameters
4. Implement additional alerting mechanisms

## Production Deployment Considerations

For production use, consider:

1. Implementing proper security for API keys and credentials
2. Setting up redundant monitoring instances
3. Using a production-grade database for storing alerts and historical data
4. Setting up proper logging and monitoring for the system itself
5. Implementing rate limiting and throttling for API calls

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
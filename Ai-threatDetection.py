"""
AI-Powered Threat Detection System for Network Security

This system analyzes Atlas traceroute data and BGP/RPKI feeds to:
1. Detect network anomalies
2. Predict potential threats
3. Automate alerts and mitigation strategies

Components:
- Atlas Data Analyzer (traceroute anomaly detection)
- BGP/RPKI Validator (route validation)
- Machine Learning Predictor (threat prediction)
- Alert System (notification mechanism)
"""

import pandas as pd
import numpy as np
import requests
import json
import time
import logging
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("threat_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ai_threat_detection")

class AtlasDataAnalyzer:
    """Component for analyzing RIPE Atlas traceroute data to detect anomalies"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://atlas.ripe.net/api/v2/"
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.historical_data = None
        
    def fetch_traceroute_data(self, measurement_ids, start_time=None, end_time=None):
        """Fetch traceroute data from RIPE Atlas API"""
        if not isinstance(measurement_ids, list):
            measurement_ids = [measurement_ids]
            
        results = []
        for measurement_id in measurement_ids:
            url = f"{self.base_url}measurements/{measurement_id}/results/"
            
            params = {}
            if start_time:
                params["start"] = start_time
            if end_time:
                params["stop"] = end_time
            if self.api_key:
                params["key"] = self.api_key
                
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                results.extend(response.json())
                logger.info(f"Successfully fetched data for measurement {measurement_id}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching data for measurement {measurement_id}: {e}")
                
        return results
    
    def extract_features(self, traceroute_data):
        """Extract relevant features from traceroute data"""
        features = []
        
        for result in traceroute_data:
            # Basic features
            rtt_values = []
            hop_count = 0
            ip_changes = 0
            prev_ip = None
            asn_changes = 0
            prev_asn = None
            
            # Process each hop
            if "result" in result:
                for hop in result.get("result", []):
                    hop_count += 1
                    
                    # Extract RTT values
                    for reply in hop.get("result", []):
                        if "rtt" in reply and reply["rtt"] is not None:
                            rtt_values.append(reply["rtt"])
                    
                    # Count IP changes
                    current_ip = None
                    for reply in hop.get("result", []):
                        if "from" in reply:
                            current_ip = reply["from"]
                            break
                    
                    if current_ip and prev_ip and current_ip != prev_ip:
                        ip_changes += 1
                    prev_ip = current_ip
                    
                    # Count ASN changes (would require ASN lookup in a real implementation)
                    # Simplified version for demonstration
                    current_asn = hop.get("asn", None)
                    if current_asn and prev_asn and current_asn != prev_asn:
                        asn_changes += 1
                    prev_asn = current_asn
            
            # Compute aggregate features
            avg_rtt = np.mean(rtt_values) if rtt_values else 0
            min_rtt = np.min(rtt_values) if rtt_values else 0
            max_rtt = np.max(rtt_values) if rtt_values else 0
            rtt_std = np.std(rtt_values) if len(rtt_values) > 1 else 0
            
            features.append({
                "timestamp": result.get("timestamp", 0),
                "hop_count": hop_count,
                "avg_rtt": avg_rtt,
                "min_rtt": min_rtt,
                "max_rtt": max_rtt,
                "rtt_std": rtt_std,
                "ip_changes": ip_changes,
                "asn_changes": asn_changes,
                "probe_id": result.get("prb_id", 0)
            })
            
        return pd.DataFrame(features)
    
    def train_anomaly_detector(self, historical_data):
        """Train the anomaly detection model on historical traceroute data"""
        if historical_data.empty:
            logger.warning("No historical data provided for training")
            return False
            
        self.historical_data = historical_data
        
        # Select numerical features
        numeric_features = historical_data.select_dtypes(include=[np.number])
        exclude_cols = ["timestamp", "probe_id"]
        feature_cols = [col for col in numeric_features.columns if col not in exclude_cols]
        
        # Scale features
        X = self.scaler.fit_transform(historical_data[feature_cols])
        
        # Train isolation forest
        self.model.fit(X)
        logger.info("Anomaly detection model trained successfully")
        
        return True
    
    def detect_anomalies(self, new_data):
        """Detect anomalies in new traceroute data"""
        if self.historical_data is None:
            logger.error("Model not trained. Call train_anomaly_detector first.")
            return None
            
        # Select numeric features
        numeric_features = new_data.select_dtypes(include=[np.number])
        exclude_cols = ["timestamp", "probe_id"]
        feature_cols = [col for col in numeric_features.columns if col not in exclude_cols]
        
        # Scale features
        X = self.scaler.transform(new_data[feature_cols])
        
        # Predict anomalies
        # Isolation Forest: -1 for anomalies, 1 for normal
        predictions = self.model.predict(X)
        anomaly_scores = self.model.decision_function(X)
        
        # Add results to the dataframe
        new_data["is_anomaly"] = [1 if pred == -1 else 0 for pred in predictions]
        new_data["anomaly_score"] = anomaly_scores
        
        logger.info(f"Detected {np.sum(new_data['is_anomaly'])} anomalies out of {len(new_data)} traceroutes")
        
        return new_data


class BGPRPKIValidator:
    """Component for validating BGP routes against RPKI data"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.rpki_cache = {}
        self.bgp_data = None
        self.model = RandomForestClassifier(random_state=42)
        
    def fetch_bgp_data(self, source="routeviews", timeframe="latest"):
        """Fetch BGP data from a specified source"""
        # In a real implementation, this would connect to a BGP data source
        # For demonstration, we'll create mock data
        
        mock_bgp_data = []
        current_time = int(time.time())
        
        # Create 100 sample BGP announcements
        for i in range(100):
            prefix = f"192.{i % 255}.{(i*3) % 255}.0/24"
            origin_asn = 64500 + (i % 100)
            
            # Introduce some potential anomalies
            if i % 20 == 0:
                # Potentially suspicious ASN
                origin_asn = 65000 + (i % 10)
            
            # Create path with length variation
            path_length = 3 + (i % 5)
            as_path = [64000 - j for j in range(path_length)]
            as_path.append(origin_asn)
            
            entry = {
                "timestamp": current_time - (i * 60),
                "prefix": prefix,
                "origin_asn": origin_asn,
                "as_path": as_path,
                "next_hop": f"10.0.0.{i % 255}",
                "communities": [f"64500:{i}", f"64500:{i+100}"],
            }
            mock_bgp_data.append(entry)
        
        self.bgp_data = pd.DataFrame(mock_bgp_data)
        logger.info(f"Fetched {len(mock_bgp_data)} BGP announcements")
        
        return self.bgp_data
    
    def fetch_rpki_data(self):
        """Fetch RPKI ROA data"""
        # In a real implementation, this would fetch ROA data from RPKI validators
        # For demonstration, we'll create mock data
        
        mock_roa_data = []
        
        # Create matching ROAs for most of our BGP data
        for i in range(80):
            prefix = f"192.{i % 255}.{(i*3) % 255}.0/24"
            max_length = 24
            asn = 64500 + (i % 100)
            
            # Introduce some invalid ROAs
            if i % 20 == 0:
                # ROA with different ASN than what we'll see in BGP
                asn = 64600 + (i % 100)
            
            roa = {
                "prefix": prefix,
                "max_length": max_length,
                "asn": asn,
                "ta": "RIPE NCC"  # Trust Anchor
            }
            mock_roa_data.append(roa)
        
        # Cache the ROA data
        for roa in mock_roa_data:
            prefix = roa["prefix"]
            if prefix not in self.rpki_cache:
                self.rpki_cache[prefix] = []
            self.rpki_cache[prefix].append(roa)
        
        logger.info(f"Fetched {len(mock_roa_data)} RPKI ROAs")
        
        return mock_roa_data
    
    def validate_routes(self, bgp_data=None):
        """Validate BGP routes against RPKI data"""
        if bgp_data is None:
            bgp_data = self.bgp_data
            
        if bgp_data is None:
            logger.error("No BGP data available. Call fetch_bgp_data first.")
            return None
            
        if not self.rpki_cache:
            self.fetch_rpki_data()
            
        validated_routes = []
        
        for _, route in bgp_data.iterrows():
            prefix = route["prefix"]
            origin_asn = route["origin_asn"]
            
            validation_state = "unknown"
            matching_roas = []
            
            # Check if we have ROAs for this prefix
            if prefix in self.rpki_cache:
                matching_roas = self.rpki_cache[prefix]
                
                # Check if any ROA validates this announcement
                for roa in matching_roas:
                    if roa["asn"] == origin_asn:
                        # Check prefix length
                        announced_prefix_length = int(prefix.split("/")[1])
                        if announced_prefix_length <= roa["max_length"]:
                            validation_state = "valid"
                            break
                
                # If we found ROAs but none validated, it's invalid
                if matching_roas and validation_state != "valid":
                    validation_state = "invalid"
            
            route_data = route.to_dict()
            route_data["validation_state"] = validation_state
            route_data["matching_roas"] = len(matching_roas)
            
            validated_routes.append(route_data)
        
        validated_df = pd.DataFrame(validated_routes)
        
        # Log validation summary
        summary = validated_df["validation_state"].value_counts()
        logger.info(f"Route validation summary: {summary.to_dict()}")
        
        return validated_df
    
    def extract_features(self, validated_routes):
        """Extract features for BGP hijack prediction model"""
        features = []
        
        for _, route in validated_routes.iterrows():
            # Basic features
            prefix_length = int(route["prefix"].split("/")[1])
            as_path_length = len(route["as_path"])
            origin_asn = route["origin_asn"]
            
            # Convert validation state to numeric
            validation_numeric = {
                "valid": 2,
                "unknown": 1,
                "invalid": 0
            }[route["validation_state"]]
            
            # More advanced features
            is_private_asn = 1 if (64512 <= origin_asn <= 65534) else 0
            
            feature_dict = {
                "timestamp": route["timestamp"],
                "prefix_length": prefix_length,
                "as_path_length": as_path_length,
                "validation_state_numeric": validation_numeric,
                "matching_roas": route["matching_roas"],
                "is_private_asn": is_private_asn,
                "origin_asn": origin_asn,
            }
            
            features.append(feature_dict)
            
        return pd.DataFrame(features)
    
    def train_hijack_detector(self, labeled_data):
        """Train the BGP hijack prediction model"""
        # In a real system, you would have labeled data with known hijacks
        # For demonstration, we'll create synthetic labels
        
        # Synthetic labels: mark all invalid routes and some unknowns as potential hijacks
        labeled_data["is_suspicious"] = (
            (labeled_data["validation_state_numeric"] == 0) | 
            ((labeled_data["validation_state_numeric"] == 1) & 
             (labeled_data["is_private_asn"] == 1))
        ).astype(int)
        
        # Features for training
        feature_cols = [
            "prefix_length", "as_path_length", "validation_state_numeric",
            "matching_roas", "is_private_asn"
        ]
        
        X = labeled_data[feature_cols]
        y = labeled_data["is_suspicious"]
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
        
        # Train the model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        logger.info(f"BGP hijack detector trained. Train accuracy: {train_score:.3f}, Test accuracy: {test_score:.3f}")
        
        # Feature importance
        importances = self.model.feature_importances_
        feature_importance = {feature: importance for feature, importance in zip(feature_cols, importances)}
        logger.info(f"Feature importance: {feature_importance}")
        
        return self.model
    
    def predict_hijacks(self, route_features):
        """Predict potential BGP hijacks"""
        if not hasattr(self.model, 'predict'):
            logger.error("Model not trained. Call train_hijack_detector first.")
            return None
            
        feature_cols = [
            "prefix_length", "as_path_length", "validation_state_numeric",
            "matching_roas", "is_private_asn"
        ]
        
        X = route_features[feature_cols]
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)[:, 1]  # Probability of class 1 (suspicious)
        
        route_features["predicted_hijack"] = predictions
        route_features["hijack_probability"] = probabilities
        
        hijack_count = np.sum(predictions)
        logger.info(f"Detected {hijack_count} potential hijacks out of {len(route_features)} routes")
        
        return route_features


class ThreatPredictor:
    """Component for integrating multiple data sources and predicting threats"""
    
    def __init__(self):
        self.atlas_analyzer = AtlasDataAnalyzer()
        self.bgp_validator = BGPRPKIValidator()
        self.combined_features = None
        
    def integrate_data(self, traceroute_analysis, bgp_analysis):
        """Integrate data from multiple sources"""
        # In a real system, you would need to correlate different data sources
        # This is a simplified demonstration
        if traceroute_analysis is None:
            logger.error("traceroute_analysis is None in integrate_data")
            # Create an empty DataFrame with required columns
            traceroute_analysis = pd.DataFrame(columns=["timestamp", "is_anomaly", "anomaly_score", 
                                                        "hop_count", "avg_rtt", "ip_changes"])
        
        if bgp_analysis is None:
            logger.error("bgp_analysis is None in integrate_data")
            # Create an empty DataFrame with required columns
            bgp_analysis = pd.DataFrame(columns=["timestamp", "predicted_hijack", "hijack_probability",
                                                "validation_state_numeric", "as_path_length", "is_private_asn"])
        
        # Group traceroute anomalies by timestamp (rounding to nearest hour)
        traceroute_analysis["hour"] = np.floor(traceroute_analysis["timestamp"] / 3600) * 3600
        traceroute_grouped = traceroute_analysis.groupby("hour").agg({
            "is_anomaly": "sum",
            "anomaly_score": "mean",
            "hop_count": "mean",
            "avg_rtt": "mean",
            "ip_changes": "mean"
        }).reset_index()
        
        # Group BGP data by timestamp hour
        bgp_analysis["hour"] = np.floor(bgp_analysis["timestamp"] / 3600) * 3600
        bgp_grouped = bgp_analysis.groupby("hour").agg({
            "predicted_hijack": "sum",
            "hijack_probability": "mean",
            "validation_state_numeric": "mean",
            "as_path_length": "mean",
            "is_private_asn": "sum"
        }).reset_index()
        
        # Merge the datasets on hour
        combined = pd.merge(
            traceroute_grouped, bgp_grouped, 
            on="hour", how="outer", 
            suffixes=("_trace", "_bgp")
        ).fillna(0)
        
        self.combined_features = combined
        logger.info(f"Integrated {len(traceroute_grouped)} traceroute periods with {len(bgp_grouped)} BGP periods")
        
        return combined
    
    def calculate_threat_score(self, combined_data=None):
        """Calculate overall threat score based on integrated data"""
        if combined_data is None:
            combined_data = self.combined_features
            
        if combined_data is None:
            logger.error("No combined data available. Call integrate_data first.")
            return None
        
        # Define weights for different components
        weights = {
            "is_anomaly": 0.2,
            "anomaly_score": -0.15,  # Lower is more anomalous
            "predicted_hijack": 0.3,
            "hijack_probability": 0.25,
            "validation_state_numeric": -0.1  # Higher is more valid
        }
        
        # Calculate normalized threat score
        combined_data["threat_score"] = 0
        for feature, weight in weights.items():
            if feature in combined_data.columns:
                # Normalize the feature to [0, 1] range
                min_val = combined_data[feature].min()
                max_val = combined_data[feature].max()
                if max_val > min_val:
                    normalized = (combined_data[feature] - min_val) / (max_val - min_val)
                else:
                    normalized = 0
                
                combined_data["threat_score"] += weight * normalized
        
        # Scale to 0-100 range
        min_score = combined_data["threat_score"].min()
        max_score = combined_data["threat_score"].max()
        if max_score > min_score:
            combined_data["threat_score"] = (
                (combined_data["threat_score"] - min_score) / (max_score - min_score) * 100
            )
        
        # Classify threat levels
        conditions = [
            combined_data["threat_score"] < 20,
            (combined_data["threat_score"] >= 20) & (combined_data["threat_score"] < 50),
            (combined_data["threat_score"] >= 50) & (combined_data["threat_score"] < 80),
            combined_data["threat_score"] >= 80
        ]
        choices = ["Low", "Medium", "High", "Critical"]
        combined_data["threat_level"] = np.select(conditions, choices, default="Unknown")
        
        logger.info("Threat scores calculated")
        level_summary = combined_data["threat_level"].value_counts()
        logger.info(f"Threat level summary: {level_summary.to_dict()}")
        
        return combined_data


class AlertSystem:
    """Component for sending alerts and initiating mitigations"""
    
    def __init__(self, email_config=None, api_config=None):
        self.email_config = email_config or {}
        self.api_config = api_config or {}
        self.alert_history = []
        self.threshold = 50  # Default threshold for alerts
        
    def set_threshold(self, threshold):
        """Set the threshold for generating alerts"""
        self.threshold = threshold
        logger.info(f"Alert threshold set to {threshold}")
        
    def generate_alerts(self, threat_data):
        """Generate alerts based on threat data"""
        alerts = []
        
        for _, event in threat_data.iterrows():
            if event["threat_score"] >= self.threshold:
                alert = {
                    "timestamp": datetime.fromtimestamp(event["hour"]),
                    "threat_score": event["threat_score"],
                    "threat_level": event["threat_level"],
                    "traceroute_anomalies": event.get("is_anomaly", 0),
                    "bgp_hijacks": event.get("predicted_hijack", 0),
                    "details": {
                        "traceroute": {
                            "anomaly_score": event.get("anomaly_score", 0),
                            "hop_count": event.get("hop_count", 0),
                            "avg_rtt": event.get("avg_rtt", 0),
                            "ip_changes": event.get("ip_changes", 0)
                        },
                        "bgp": {
                            "hijack_probability": event.get("hijack_probability", 0),
                            "validation_state": event.get("validation_state_numeric", 0),
                            "as_path_length": event.get("as_path_length", 0),
                            "private_asns": event.get("is_private_asn", 0)
                        }
                    },
                    "alert_id": f"ALERT-{int(time.time())}-{len(self.alert_history)}"
                }
                
                alerts.append(alert)
                self.alert_history.append(alert)
                
        logger.info(f"Generated {len(alerts)} alerts")
        return alerts
    
    def send_email_alerts(self, alerts, recipients=None):
        """Send email alerts (simulated)"""
        if not alerts:
            logger.info("No alerts to send via email")
            return
            
        recipients = recipients or self.email_config.get("default_recipients", ["admin@example.com"])
        
        for alert in alerts:
            # In a real implementation, this would send an actual email
            logger.info(f"[SIMULATED EMAIL] To: {recipients}, Subject: {alert['threat_level']} Threat Alert - Score: {alert['threat_score']:.1f}")
            logger.info(f"[SIMULATED EMAIL] Body: Detected {alert['traceroute_anomalies']} traceroute anomalies and {alert['bgp_hijacks']} potential BGP hijacks at {alert['timestamp']}")
            
    def send_api_notifications(self, alerts, endpoints=None):
        """Send API notifications to ISPs or other systems (simulated)"""
        if not alerts:
            logger.info("No alerts to send via API")
            return
            
        endpoints = endpoints or self.api_config.get("notification_endpoints", ["https://api.example.com/notifications"])
        
        for alert in alerts:
            # Filter for high-severity alerts for API notifications
            if alert["threat_level"] in ["High", "Critical"]:
                # In a real implementation, this would make API calls
                for endpoint in endpoints:
                    logger.info(f"[SIMULATED API CALL] POST to {endpoint}")
                    logger.info(f"[SIMULATED API CALL] Data: {json.dumps(alert)}")
    
    def suggest_mitigations(self, alerts):
        """Suggest mitigations based on alert details"""
        mitigations = []
        
        for alert in alerts:
            mitigation = {
                "alert_id": alert["alert_id"],
                "timestamp": alert["timestamp"],
                "threat_level": alert["threat_level"],
                "actions": []
            }
            
            # Suggest actions based on the type of threat
            if alert["bgp_hijacks"] > 0:
                mitigation["actions"].append({
                    "type": "BGP_MITIGATION",
                    "description": "Potential BGP hijack detected. Verify and contact affected ISPs.",
                    "priority": "High" if alert["threat_level"] in ["High", "Critical"] else "Medium",
                    "automated": False
                })
                
            if alert["traceroute_anomalies"] > 0:
                mitigation["actions"].append({
                    "type": "TRACEROUTE_INVESTIGATION",
                    "description": "Network path anomalies detected. Investigate routing changes.",
                    "priority": "Medium",
                    "automated": False
                })
                
            # Add general actions for all threats
            mitigation["actions"].append({
                "type": "MONITORING",
                "description": "Increase monitoring frequency for affected networks",
                "priority": "Low",
                "automated": True
            })
            
            mitigations.append(mitigation)
            
        logger.info(f"Generated {len(mitigations)} mitigation plans")
        return mitigations


class ThreatDetectionSystem:
    """Main class integrating all components of the threat detection system"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.atlas_analyzer = AtlasDataAnalyzer(api_key=self.config.get("95979aa4-6398-43ec-a455-50334269a44c"))
        self.bgp_validator = BGPRPKIValidator(api_key=self.config.get("bgp_api_key"))
        self.threat_predictor = ThreatPredictor()
        self.alert_system = AlertSystem(
            email_config=self.config.get("email_config"),
            api_config=self.config.get("api_config")
        )
        
    def initialize(self):
        """Initialize the system with historical data and model training"""
        logger.info("Initializing AI Threat Detection System")
        
        # Initialize Atlas data analyzer
        # In a real system, you would fetch historical data
        historical_traceroutes = self.atlas_analyzer.fetch_traceroute_data(
            measurement_ids=[1234, 5678],  # Example IDs
            start_time=int(time.time()) - (30 * 24 * 3600)  # Last 30 days
        )
        historical_features = self.atlas_analyzer.extract_features(historical_traceroutes)
        self.atlas_analyzer.train_anomaly_detector(historical_features)
        
        # Initialize BGP validator
        historical_bgp = self.bgp_validator.fetch_bgp_data()
        self.bgp_validator.fetch_rpki_data()
        validated_routes = self.bgp_validator.validate_routes(historical_bgp)
        route_features = self.bgp_validator.extract_features(validated_routes)
        self.bgp_validator.train_hijack_detector(route_features)
        
        logger.info("System initialization complete")
        
    def run_detection_cycle(self):
        """Run a complete detection cycle"""
        logger.info("Starting threat detection cycle")
        
        # Fetch and analyze new traceroute data
        try:
            new_traceroutes = self.atlas_analyzer.fetch_traceroute_data(
                measurement_ids=[1234, 5678],  # Example IDs
                start_time=int(time.time()) - (24 * 3600)  # Last 24 hours
            )
            if not new_traceroutes:
                logger.warning("No traceroute data returned")
                traceroute_analysis = None
            else:    
                traceroute_features = self.atlas_analyzer.extract_features(new_traceroutes)
                traceroute_analysis = self.atlas_analyzer.detect_anomalies(traceroute_features)
        except Exception as e:
            logger.error(f"Error in traceroute analysis: {e}")
            traceroute_analysis = None


            # Fetch and analyze new BGP data
        try:
            new_bgp = self.bgp_validator.fetch_bgp_data()
            if new_bgp is None or new_bgp.empty:
                logger.warning("No BGP data returned")
                bgp_analysis = None
            else:
                validated_routes = self.bgp_validator.validate_routes(new_bgp)
                route_features = self.bgp_validator.extract_features(validated_routes)
                bgp_analysis = self.bgp_validator.predict_hijacks(route_features)
        except Exception as e:
            logger.error(f"Error in BGP analysis: {e}")
            bgp_analysis = None
        
        # Integrate data and predict threats
        integrated_data = self.threat_predictor.integrate_data(traceroute_analysis, bgp_analysis)
        threat_assessment = self.threat_predictor.calculate_threat_score(integrated_data)
        
        # Generate alerts and mitigations
        alerts = self.alert_system.generate_alerts(threat_assessment)
        mitigations = self.alert_system.suggest_mitigations(alerts)
        
        # Send notifications
        self.alert_system.send_email_alerts(alerts)
        self.alert_system.send_api_notifications(alerts)
        
        # Prepare results
        results = {
            "run_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "traceroute_anomalies": traceroute_analysis["is_anomaly"].sum(),
            "bgp_hijacks": bgp_analysis["predicted_hijack"].sum(),
            "threat_levels": threat_assessment["threat_level"].value_counts().to_dict(),
            "alerts_generated": len(alerts),
            "mitigations_suggested": len(mitigations)
        }
        
        logger.info(f"Threat detection cycle completed: {results}")
        return results
    
    def generate_report(self, results):
        """Generate a summary report of the detection cycle"""
        report = f"""
        AI-Powered Threat Detection System - Summary Report
        ===================================================
        Generated: {results['run_time']}
        
        Detection Results:
        -----------------
        Traceroute Anomalies Detected: {results['traceroute_anomalies']}
        Potential BGP Hijacks Detected: {results['bgp_hijacks']}
        
        Threat Levels:
        -------------
        {' | '.join([f"{level}: {count}" for level, count in results['threat_levels'].items()])}
        
        Actions Taken:
        -------------
        Alerts Generated: {results['alerts_generated']}
        Mitigation Plans Suggested: {results['mitigations_suggested']}
        
        System Status: Operational
        """
        
        logger.info("Report generated successfully")
        return report

# Example usage
if __name__ == "__main__":
    # Configuration
    config = {
        "atlas_api_key": "your_atlas_api_key_here",
        "bgp_api_key": "your_bgp_api_key_here",
        "email_config": {
            "default_recipients": ["security-team@example.com", "noc@example.com"],
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "smtp_user": "alerts@example.com",
            "smtp_password": "password123"
        },
        "api_config": {
            "notification_endpoints": [
                "https://api.example.com/security-notifications",
                "https://api.ispprovider.com/route-security/alerts"
            ]
        }
    }
    
    # Initialize the system
    system = ThreatDetectionSystem(config)
    system.initialize()
    
    # Run a detection cycle
    results = system.run_detection_cycle()
    
    # Generate and print report
    report = system.generate_report(results)
    print(report)


# Command-line interface
def main():
    """Command-line interface for the threat detection system"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI-Powered Threat Detection System for Network Security")
    parser.add_argument("--config", help="Path to configuration file", default="config.json")
    parser.add_argument("--mode", choices=["initialize", "detect", "report", "full"], default="full",
                    help="Operation mode (initialize, detect, report, or full cycle)")
    parser.add_argument("--alert-threshold", type=float, default=50.0,
                    help="Threshold for generating alerts (0-100)")
    parser.add_argument("--output", help="Output file for report", default="threat_report.txt")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    try:
        with open(args.config, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.warning(f"Configuration file {args.config} not found. Using default configuration.")
        config = {}
    
    # Create and configure the system
    system = ThreatDetectionSystem(config)
    
    # Set alert threshold
    system.alert_system.set_threshold(args.alert_threshold)
    
    # Execute selected mode
    if args.mode in ["initialize", "full"]:
        system.initialize()
        
    if args.mode in ["detect", "full"]:
        results = system.run_detection_cycle()
        
    if args.mode in ["report", "full"]:
        if "results" not in locals():
            # If we didn't run detection, use dummy results
            results = {
                "run_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "traceroute_anomalies": 0,
                "bgp_hijacks": 0,
                "threat_levels": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                "alerts_generated": 0,
                "mitigations_suggested": 0
            }
            
        report = system.generate_report(results)
        
        # Output report
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            logger.info(f"Report written to {args.output}")
        else:
            print(report)
    
    logger.info("AI Threat Detection System execution completed")


if __name__ == "__main__":
    main()
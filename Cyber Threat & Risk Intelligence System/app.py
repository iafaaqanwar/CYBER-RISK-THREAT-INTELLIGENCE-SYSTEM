"""
============================================================
 app.py — Flask Backend Server
 Cyber Risk & Threat Intelligence System
============================================================
 Core web application that:
   - Loads the trained ML model pipeline (model.pkl)
   - Initializes Prolog engine with knowledge_base.pl
   - Provides REST API for .pcap file upload analysis
   - Provides WebSocket interface for live packet capture
   - Integrates the encrypted threat log vault
   - Serves the real-time dashboard frontend
============================================================
"""

import os
import sys
import json
import time
import threading
import asyncio
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit

# --- Conditional Imports (graceful degradation) ---
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("[WARN] pyshark not installed. Packet capture features disabled.")

# --- Configure SWI-Prolog paths on Windows if not set ---
if sys.platform == "win32" and "SWI_HOME_DIR" not in os.environ:
    default_swipl_path = r"C:\Program Files\swipl"
    if os.path.exists(default_swipl_path):
        os.environ["SWI_HOME_DIR"] = default_swipl_path
        os.environ["PATH"] = os.path.join(default_swipl_path, "bin") + os.pathsep + os.environ.get("PATH", "")
        if hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(os.path.join(default_swipl_path, "bin"))
            except Exception:
                pass

try:
    from pyswip import Prolog
    PYSWIP_AVAILABLE = True
except (ImportError, Exception) as e:
    PYSWIP_AVAILABLE = False
    print(f"[WARN] pyswip loading failed: {e}. Prolog reasoning will use fallback.")
    print("[INFO] To enable SWI-Prolog reasoning, please install SWI-Prolog (x64) and add its bin/ folder to the system PATH.")

# ============================================================
# Flask Application Configuration
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
    template_folder=os.path.join(BASE_DIR, "templates"),
)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "cyber-risk-default-key-2026")
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")
app.config["REPORTS_FOLDER"] = os.path.join(BASE_DIR, "reports")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload

# Initialize Flask-SocketIO with eventlet for async support
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ============================================================
# Global State
# ============================================================
ml_pipeline = None        # Loaded ML model pipeline dict
prolog_engine = None      # PySwip Prolog instance
capture_active = False    # Flag for live capture thread
capture_thread = None     # Reference to the capture thread


# ============================================================
# Startup: Load ML Model
# ============================================================
def load_ml_model():
    """
    Loads the trained ML pipeline from model.pkl.

    The pipeline dict contains:
      - 'model':         Trained KNN/NaiveBayes classifier
      - 'scaler':        Fitted StandardScaler
      - 'encoders':      Dict of LabelEncoders for categorical features
      - 'feature_cols':  List of feature column names
      - 'label_encoder': LabelEncoder for the target column

    Returns:
        dict or None: The loaded pipeline, or None if loading fails.
    """
    model_path = os.path.join(BASE_DIR, "model.pkl")

    if not os.path.exists(model_path):
        print("[WARN] model.pkl not found. Train the model first "
              "using 'python train_model.py'.")
        return None

    try:
        pipeline = joblib.load(model_path)
        print(f"[INFO] ML model loaded successfully from {model_path}")
        print(f"[INFO] Model type: {type(pipeline['model']).__name__}")
        print(f"[INFO] Feature columns: {len(pipeline['feature_cols'])}")
        print(f"[INFO] Target classes: "
              f"{list(pipeline['label_encoder'].classes_)}")
        return pipeline

    except Exception as e:
        print(f"[ERROR] Failed to load model.pkl: {e}")
        return None


# ============================================================
# Startup: Initialize Prolog Engine
# ============================================================
def init_prolog():
    """
    Initializes the PySwip Prolog engine and loads
    the knowledge_base.pl file.

    Returns:
        Prolog instance or None if initialization fails.
    """
    if not PYSWIP_AVAILABLE:
        print("[WARN] PySwip unavailable — using fallback threat diagnosis.")
        return None

    try:
        prolog = Prolog()
        kb_path = os.path.join(BASE_DIR, "knowledge_base.pl")

        if not os.path.exists(kb_path):
            print(f"[ERROR] knowledge_base.pl not found at {kb_path}")
            return None

        # Prolog requires forward slashes in file paths
        kb_path_prolog = kb_path.replace("\\", "/")
        prolog.consult(kb_path_prolog)
        print(f"[INFO] Prolog knowledge base loaded: {kb_path}")
        return prolog

    except Exception as e:
        print(f"[ERROR] Failed to initialize Prolog engine: {e}")
        return None


# ============================================================
# Packet Feature Extraction (pyshark)
# ============================================================
def extract_packet_features(packet) -> dict:
    """
    Extracts relevant network features from a pyshark packet object.

    Args:
        packet: A pyshark Packet object.

    Returns:
        dict: Extracted features including protocol, IPs, ports,
              packet length, and timestamp. Returns None if
              extraction fails (e.g., non-IP packet).
    """
    try:
        features = {
            "timestamp": str(packet.sniff_time) if hasattr(packet, "sniff_time")
                         else datetime.now().isoformat(),
            "protocol": "unknown",
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "src_port": 0,
            "dst_port": 0,
            "length": int(packet.length) if hasattr(packet, "length") else 0,
            "info": str(packet.layers[-1].layer_name)
                    if packet.layers else "unknown",
        }

        # --- Extract IP layer data ---
        if hasattr(packet, "ip"):
            features["src_ip"] = str(packet.ip.src)
            features["dst_ip"] = str(packet.ip.dst)
            features["protocol"] = str(packet.transport_layer or "ip").lower()

        elif hasattr(packet, "ipv6"):
            features["src_ip"] = str(packet.ipv6.src)
            features["dst_ip"] = str(packet.ipv6.dst)
            features["protocol"] = str(packet.transport_layer or "ipv6").lower()

        # --- Extract transport layer ports ---
        if hasattr(packet, "tcp"):
            features["src_port"] = int(packet.tcp.srcport)
            features["dst_port"] = int(packet.tcp.dstport)
            features["protocol"] = "tcp"
            # Extract TCP flags for scan detection
            if hasattr(packet.tcp, "flags"):
                features["tcp_flags"] = str(packet.tcp.flags)

        elif hasattr(packet, "udp"):
            features["src_port"] = int(packet.udp.srcport)
            features["dst_port"] = int(packet.udp.dstport)
            features["protocol"] = "udp"

        elif hasattr(packet, "icmp"):
            features["protocol"] = "icmp"

        # Check for HTTP or raw payload patterns (SQL injection, XSS)
        payload_text = ""
        if hasattr(packet, "http"):
            if hasattr(packet.http, "request_uri"):
                payload_text += str(packet.http.request_uri).lower()
            if hasattr(packet.http, "file_data"):
                payload_text += str(packet.http.file_data).lower()
        elif hasattr(packet, "tcp") and hasattr(packet.tcp, "payload"):
            try:
                # payload is hex string
                hex_payload = packet.tcp.payload.replace(":", "")
                payload_text += bytes.fromhex(hex_payload).decode("utf-8", errors="ignore").lower()
            except Exception:
                pass

        if payload_text:
            if "select" in payload_text or "union" in payload_text or "' or" in payload_text or "1=1" in payload_text or "'--" in payload_text:
                features["payload_indicator"] = "sql_pattern"
            elif "<script>" in payload_text or "javascript:" in payload_text or "alert(" in payload_text:
                features["payload_indicator"] = "xss_pattern"

        return features

    except Exception:
        return None


# ============================================================
# ML Classification
# ============================================================
def classify_packet(features: dict) -> dict:
    """
    Classifies a packet as normal or anomalous using the trained
    ML model.

    Since the ML model was trained on tabular CSV data (NSL-KDD),
    we map raw packet features to the closest available feature
    representation for prediction.

    Args:
        features: Dict of extracted packet features.

    Returns:
        dict with 'prediction' (str) and 'confidence' (float).
    """
    global ml_pipeline

    if ml_pipeline is None:
        # Fallback: heuristic-based classification
        return _heuristic_classify(features)

    try:
        model = ml_pipeline["model"]
        scaler = ml_pipeline["scaler"]
        label_encoder = ml_pipeline["label_encoder"]
        feature_cols = ml_pipeline["feature_cols"]

        # Build a feature vector from packet data.
        # Map packet features to numerical values the model can process.
        n_features = len(feature_cols)
        feature_vector = np.zeros(n_features)

        # Encode protocol as numeric
        protocol_map = {"tcp": 1, "udp": 2, "icmp": 3, "http": 4, "dns": 5}
        feature_vector[0] = protocol_map.get(features.get("protocol", ""), 0)

        # Use port and length information
        if n_features > 1:
            feature_vector[1] = features.get("src_port", 0)
        if n_features > 2:
            feature_vector[2] = features.get("dst_port", 0)
        if n_features > 3:
            feature_vector[3] = features.get("length", 0)

        # Scale features
        feature_vector = scaler.transform(feature_vector.reshape(1, -1))

        # Predict
        prediction_idx = model.predict(feature_vector)[0]
        prediction_label = label_encoder.inverse_transform([prediction_idx])[0]

        # Get confidence via prediction probabilities if available
        confidence = 0.85  # Default confidence
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(feature_vector)[0]
            confidence = float(max(proba))

        # Determine if anomalous
        # Check if the predicted label represents normal traffic
        normal_keywords = ["normal", "benign", "safe", "legitimate"]
        is_anomalous = not any(
            kw in str(prediction_label).lower() for kw in normal_keywords
        )

        # Override: if a payload indicator is set (e.g. SQL injection or XSS pattern), it's anomalous!
        if features.get("payload_indicator") in ("sql_pattern", "xss_pattern"):
            is_anomalous = True
            prediction_label = "anomaly"

        return {
            "prediction": str(prediction_label),
            "is_anomalous": is_anomalous,
            "confidence": round(confidence, 4),
        }

    except Exception as e:
        print(f"[ERROR] ML classification failed: {e}")
        return _heuristic_classify(features)


def _heuristic_classify(features: dict) -> dict:
    """
    Fallback heuristic classifier when the ML model is unavailable.
    Uses simple rule-based logic to flag suspicious traffic.

    Args:
        features: Dict of extracted packet features.

    Returns:
        dict with 'prediction', 'is_anomalous', and 'confidence'.
    """
    suspicious_ports = {4444, 5555, 31337, 6667, 1337, 9001, 12345}
    dst_port = features.get("dst_port", 0)
    length = features.get("length", 0)

    is_anomalous = False
    prediction = "normal"
    confidence = 0.6

    # Override: check payload indicator first
    if features.get("payload_indicator") in ("sql_pattern", "xss_pattern"):
        is_anomalous = True
        prediction = "anomaly"
        confidence = 0.95
    elif dst_port in suspicious_ports:
        is_anomalous = True
        prediction = "anomaly"
        confidence = 0.9
    elif length > 10000:
        is_anomalous = True
        prediction = "anomaly"
        confidence = 0.7
    elif dst_port == 0 and features.get("protocol") == "tcp":
        is_anomalous = True
        prediction = "anomaly"
        confidence = 0.75

    return {
        "prediction": prediction,
        "is_anomalous": is_anomalous,
        "confidence": confidence,
    }


# ============================================================
# Prolog Threat Diagnosis
# ============================================================
def diagnose_threat(features: dict) -> dict:
    """
    Queries the Prolog knowledge base to diagnose the specific
    attack type, risk level, and mitigation strategy.

    Args:
        features: Dict of extracted packet features.

    Returns:
        dict with 'threat_type', 'risk_level', 'mitigation'.
    """
    global prolog_engine

    protocol = features.get("protocol", "tcp")
    dst_port = features.get("dst_port", 0)

    # Determine the payload indicator based on packet characteristics
    payload_indicator = _infer_payload_indicator(features)

    if prolog_engine is not None:
        try:
            # Build Prolog query
            query = (
                f"diagnose({protocol}, {dst_port}, {payload_indicator}, "
                f"diagnosis(ThreatName, RiskRating, MitigationAction))"
            )

            results = list(prolog_engine.query(query))

            if results:
                result = results[0]
                return {
                    "threat_type": str(result.get("ThreatName", "unknown_threat")),
                    "risk_level": str(result.get("RiskRating", "low")),
                    "mitigation": str(result.get("MitigationAction", "Manual review required.")),
                }

        except Exception as e:
            print(f"[ERROR] Prolog query failed: {e}")

    # Fallback: Python-based diagnosis
    return _fallback_diagnose(protocol, dst_port, payload_indicator)


def _infer_payload_indicator(features: dict) -> str:
    """
    Infers a Prolog-compatible payload indicator atom from
    packet features using heuristic rules.

    Args:
        features: Dict of extracted packet features.

    Returns:
        str: A Prolog atom representing the payload indicator.
    """
    if "payload_indicator" in features:
        return features["payload_indicator"]

    protocol = features.get("protocol", "")
    dst_port = features.get("dst_port", 0)
    length = features.get("length", 0)
    tcp_flags = features.get("tcp_flags", "")

    # ICMP ping flood detection
    if protocol == "icmp":
        return "ping_flood"

    # TCP flag analysis
    if protocol == "tcp":
        # SYN scan: only SYN flag set
        if tcp_flags and "0x002" in str(tcp_flags):
            return "syn_scan" if length < 100 else "syn_flood"
        # FIN scan
        if tcp_flags and "0x001" in str(tcp_flags):
            return "fin_scan"
        # XMAS scan (FIN+PSH+URG)
        if tcp_flags and "0x029" in str(tcp_flags):
            return "xmas_scan"
        # NULL scan
        if tcp_flags and "0x000" in str(tcp_flags):
            return "null_scan"

    # Port-based heuristics
    if dst_port in (4444, 5555):
        return "reverse_shell"
    if dst_port == 22 or dst_port == 3389:
        return "repeated_auth"
    if dst_port == 53 and length > 512:
        return "large_dns_query"
    if dst_port in (80, 443, 8080) and length > 5000:
        return "large_outbound"

    # Default
    return "syn_flood" if protocol == "tcp" else "udp_flood"


def _fallback_diagnose(protocol: str, dst_port: int,
                       payload_indicator: str) -> dict:
    """
    Python-based fallback diagnosis when Prolog is unavailable.
    Mirrors the Prolog knowledge base logic.

    Args:
        protocol:          Network protocol string.
        dst_port:          Destination port number.
        payload_indicator: Inferred payload indicator.

    Returns:
        dict with 'threat_type', 'risk_level', 'mitigation'.
    """
    # Threat type mapping (mirrors knowledge_base.pl)
    threat_map = {
        "syn_flood": "ddos", "udp_flood": "ddos", "ping_flood": "ddos",
        "http_flood": "ddos",
        "syn_scan": "port_scan", "fin_scan": "port_scan",
        "xmas_scan": "port_scan", "null_scan": "port_scan",
        "sql_pattern": "sql_injection",
        "xss_pattern": "xss_attack",
        "repeated_auth": "brute_force",
        "large_dns_query": "dns_tunneling",
        "reverse_shell": "c2_beacon",
        "large_outbound": "data_exfiltration",
        "known_malware_sig": "malware_comm",
    }

    risk_map = {
        "ddos": "critical", "sql_injection": "critical",
        "c2_beacon": "critical", "data_exfiltration": "critical",
        "mitm_attack": "critical",
        "brute_force": "high", "xss_attack": "high",
        "malware_comm": "high", "dns_tunneling": "high",
        "port_scan": "medium",
        "unknown_threat": "low",
    }

    mitigation_map = {
        "ddos": "Deploy rate limiting and SYN cookies. Enable DDoS protection.",
        "port_scan": "Block source IP. Enable port scan detection on IDS/IPS.",
        "sql_injection": "Deploy WAF with SQL injection ruleset. Sanitize inputs.",
        "xss_attack": "Implement CSP headers. Sanitize all user-generated output.",
        "brute_force": "Enforce account lockout. Implement MFA.",
        "dns_tunneling": "Monitor DNS query lengths. Block tunneling tools.",
        "c2_beacon": "CRITICAL: Isolate host. Block C2 IP/domain.",
        "data_exfiltration": "CRITICAL: Block outbound from affected host.",
        "malware_comm": "Quarantine endpoint. Update antivirus signatures.",
        "unknown_threat": "Flag for manual SOC review.",
    }

    threat_type = threat_map.get(payload_indicator, "unknown_threat")
    risk_level = risk_map.get(threat_type, "low")
    mitigation = mitigation_map.get(threat_type, "Manual review required.")

    return {
        "threat_type": threat_type,
        "risk_level": risk_level,
        "mitigation": mitigation,
    }


# ============================================================
# MODE 1: PCAP File Upload Analysis
# ============================================================
@app.route("/upload", methods=["POST"])
def upload_pcap():
    """
    Handles .pcap file upload and analysis.

    Flow:
      1. Receives uploaded .pcap file.
      2. Parses packets via pyshark.FileCapture.
      3. Extracts features from each packet.
      4. Classifies packets using the ML model.
      5. Diagnoses anomalous packets via Prolog.
      6. Logs threats to the encrypted vault.
      7. Returns JSON results to the frontend.

    Returns:
        JSON response with analysis results.
    """
    # Create and set a new event loop for this request thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Validate file presence
    if "pcap_file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["pcap_file"]

    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    # Validate file extension
    allowed_extensions = {".pcap", ".pcapng", ".cap"}
    _, ext = os.path.splitext(file.filename)
    if ext.lower() not in allowed_extensions:
        return jsonify({
            "error": f"Invalid file type '{ext}'. "
                     f"Allowed: {', '.join(allowed_extensions)}"
        }), 400

    # Save uploaded file
    filename = f"{int(time.time())}_{file.filename}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)
    print(f"[INFO] PCAP file saved: {filepath}")

    if not PYSHARK_AVAILABLE:
        return jsonify({
            "error": "pyshark is not installed. Cannot parse .pcap files."
        }), 500

    # Parse and analyze packets
    results = {
        "filename": file.filename,
        "total_packets": 0,
        "normal_packets": 0,
        "anomalous_packets": 0,
        "threats": [],
        "packet_timeline": [],
    }

    try:
        cap = pyshark.FileCapture(filepath, keep_packets=False)

        for packet in cap:
            results["total_packets"] += 1

            # Extract features
            features = extract_packet_features(packet)
            if features is None:
                continue

            # Classify with ML model
            classification = classify_packet(features)
            features["classification"] = classification

            # Build timeline entry for chart
            timeline_entry = {
                "timestamp": features["timestamp"],
                "length": features["length"],
                "is_anomalous": classification["is_anomalous"],
            }
            results["packet_timeline"].append(timeline_entry)

            if classification["is_anomalous"]:
                results["anomalous_packets"] += 1

                # Diagnose via Prolog
                diagnosis = diagnose_threat(features)

                threat_entry = {
                    "packet_no": results["total_packets"],
                    "src_ip": features["src_ip"],
                    "dst_ip": features["dst_ip"],
                    "protocol": features["protocol"],
                    "dst_port": features["dst_port"],
                    "length": features["length"],
                    "prediction": classification["prediction"],
                    "confidence": classification["confidence"],
                    "threat_type": diagnosis["threat_type"],
                    "risk_level": diagnosis["risk_level"],
                    "mitigation": diagnosis["mitigation"],
                    "timestamp": features["timestamp"],
                }
                results["threats"].append(threat_entry)

                # Log to encrypted vault
                _log_threat_to_vault(threat_entry)

            else:
                results["normal_packets"] += 1

            # Limit processing to 10,000 packets for performance
            if results["total_packets"] >= 10000:
                print("[INFO] Packet limit reached (10,000). Stopping parse.")
                break

        cap.close()

    except Exception as e:
        print(f"[ERROR] PCAP analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

    finally:
        # Clean up uploaded file after analysis
        if 'filepath' in locals():
            try:
                os.remove(filepath)
            except OSError:
                pass
        try:
            loop.close()
        except Exception:
            pass

    print(f"[INFO] Analysis complete: {results['total_packets']} packets, "
          f"{results['anomalous_packets']} anomalous")

    return jsonify(results)


# ============================================================
# MODE 2: Live Packet Capture (WebSocket) — Simulated Demo
# ============================================================
import random

# --- Realistic IP pools for simulated traffic ---
_INTERNAL_IPS = [
    "192.168.1.5", "192.168.1.12", "192.168.1.34", "192.168.1.100",
    "192.168.1.107", "10.0.0.15", "10.0.0.22", "10.0.0.50",
]
_EXTERNAL_IPS = [
    "142.250.185.206", "151.101.1.140", "104.244.42.65",
    "13.107.42.14", "52.96.166.162", "172.217.14.100",
    "31.13.71.36", "157.240.1.35", "93.184.216.34",
    "23.215.0.136", "198.41.209.150", "34.107.243.93",
]
_ATTACKER_IPS = [
    "185.220.101.45", "45.33.32.156", "91.219.237.229",
    "194.5.73.6", "103.75.201.2", "212.129.52.5",
    "5.188.86.250", "178.128.23.9",
]

def _generate_normal_packet():
    """Generate a realistic normal traffic packet (HTTP/HTTPS/DNS browsing)."""
    scenario = random.choice(["https", "https", "https", "http", "dns", "dns"])

    src_ip = random.choice(_INTERNAL_IPS)
    dst_ip = random.choice(_EXTERNAL_IPS)

    if scenario == "https":
        return {
            "protocol": "tcp",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 443,
            "length": random.randint(60, 1500),
            "tcp_flags": "0x018",
            "info": "tls",
        }
    elif scenario == "http":
        return {
            "protocol": "tcp",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 80,
            "length": random.randint(200, 1200),
            "tcp_flags": "0x018",
            "info": "http",
        }
    else:  # dns
        return {
            "protocol": "udp",
            "src_ip": src_ip,
            "dst_ip": "8.8.8.8" if random.random() > 0.5 else "1.1.1.1",
            "src_port": random.randint(49152, 65535),
            "dst_port": 53,
            "length": random.randint(60, 120),
            "info": "dns",
        }


def _generate_attack_packet():
    """Generate a simulated attack packet — one of several threat types."""
    attack = random.choices(
        ["syn_flood", "sql_injection", "xss", "port_scan",
         "brute_force", "c2_beacon", "dns_tunnel", "icmp_flood",
         "data_exfil"],
        weights=[20, 15, 10, 15, 10, 8, 7, 10, 5],
        k=1
    )[0]

    attacker = random.choice(_ATTACKER_IPS)
    victim = random.choice(_INTERNAL_IPS)

    if attack == "syn_flood":
        return {
            "protocol": "tcp",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 8080]),
            "length": random.randint(40, 74),
            "tcp_flags": "0x002",  # SYN only
            "info": "tcp",
        }
    elif attack == "sql_injection":
        return {
            "protocol": "tcp",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": random.randint(49152, 65535),
            "dst_port": 80,
            "length": random.randint(400, 1800),
            "tcp_flags": "0x018",
            "info": "http",
            "payload_indicator": "sql_pattern",
        }
    elif attack == "xss":
        return {
            "protocol": "tcp",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": random.randint(49152, 65535),
            "dst_port": 80,
            "length": random.randint(300, 1500),
            "tcp_flags": "0x018",
            "info": "http",
            "payload_indicator": "xss_pattern",
        }
    elif attack == "port_scan":
        return {
            "protocol": "tcp",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": random.randint(40000, 65535),
            "dst_port": random.choice([21, 22, 23, 25, 80, 110, 135,
                                        139, 443, 445, 993, 3306,
                                        3389, 5432, 8080, 8443]),
            "length": random.randint(40, 60),
            "tcp_flags": random.choice(["0x002", "0x001", "0x029", "0x000"]),
            "info": "tcp",
        }
    elif attack == "brute_force":
        return {
            "protocol": "tcp",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([22, 3389]),
            "length": random.randint(100, 400),
            "tcp_flags": "0x018",
            "info": "ssh" if random.random() > 0.5 else "rdp",
        }
    elif attack == "c2_beacon":
        return {
            "protocol": "tcp",
            "src_ip": victim,  # outbound from compromised host
            "dst_ip": attacker,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([4444, 5555]),
            "length": random.randint(80, 600),
            "tcp_flags": "0x018",
            "info": "tcp",
        }
    elif attack == "dns_tunnel":
        return {
            "protocol": "udp",
            "src_ip": victim,
            "dst_ip": attacker,
            "src_port": random.randint(49152, 65535),
            "dst_port": 53,
            "length": random.randint(520, 900),  # abnormally large DNS
            "info": "dns",
        }
    elif attack == "icmp_flood":
        return {
            "protocol": "icmp",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": 0,
            "dst_port": 0,
            "length": random.randint(64, 1500),
            "info": "icmp",
        }
    else:  # data_exfil
        return {
            "protocol": "tcp",
            "src_ip": victim,
            "dst_ip": attacker,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([80, 443, 8080]),
            "length": random.randint(5000, 15000),
            "tcp_flags": "0x018",
            "info": "http",
        }


@socketio.on("start_capture")
def handle_start_capture(data=None):
    """
    WebSocket event handler: starts live packet capture (simulated).

    Launches a background task that generates realistic simulated
    network packets — a mix of normal traffic and various attack
    scenarios. Each packet passes through the real ML classifier
    and Prolog diagnosis engine.

    If a capture is already running (e.g. leftover from a previous
    page load), it is stopped first before starting fresh.

    Args:
        data: Optional dict with 'interface' key (accepted for
              UI compatibility but not used for simulation).
    """
    global capture_active, capture_thread

    # If a previous capture is still running, stop it first
    if capture_active:
        capture_active = False
        # Give the old task a moment to notice the flag and exit
        socketio.sleep(0.5)

    interface = None
    if data and "interface" in data:
        interface = data["interface"]

    capture_active = True

    # Use socketio.start_background_task (NOT threading.Thread)
    # This works correctly with eventlet's green-thread scheduler
    capture_thread = socketio.start_background_task(
        target=_live_capture_worker,
        interface=interface,
    )

    emit("capture_status", {"status": "started"})
    print(f"[INFO] Live capture started on interface: {interface or 'default'} (simulated mode)")


@socketio.on("stop_capture")
def handle_stop_capture():
    """
    WebSocket event handler: stops live packet capture.
    Sets the capture_active flag to False, which causes
    the background capture thread to exit gracefully.
    """
    global capture_active

    capture_active = False
    emit("capture_status", {"status": "stopped"})
    print("[INFO] Live capture stopped by user.")


def _live_capture_worker(interface=None):
    """
    Background worker thread for live packet capture (simulated).

    Generates realistic dummy packets mixing normal web traffic
    with various attack scenarios (DDoS, SQL injection, XSS,
    port scans, brute force, C2 beacons, DNS tunneling, data
    exfiltration). Each packet passes through the real
    classify_packet() and diagnose_threat() pipeline.

    Args:
        interface: Network interface name (accepted for
                   compatibility, not used in simulation).
    """
    global capture_active

    try:
        packet_count = 0

        # Brief initial delay to let frontend UI settle
        socketio.sleep(0.5)

        while capture_active:
            packet_count += 1

            # ~35% chance of attack packet for a compelling demo
            is_attack = random.random() < 0.35
            if is_attack:
                features = _generate_attack_packet()
            else:
                features = _generate_normal_packet()

            # Add timestamp
            features["timestamp"] = datetime.now().isoformat()

            # --- Run through the REAL ML classification pipeline ---
            classification = classify_packet(features)

            # Build packet data for frontend
            packet_data = {
                "packet_no": packet_count,
                "timestamp": features["timestamp"],
                "src_ip": features["src_ip"],
                "dst_ip": features["dst_ip"],
                "protocol": features["protocol"],
                "dst_port": features["dst_port"],
                "length": features["length"],
                "prediction": classification["prediction"],
                "is_anomalous": classification["is_anomalous"],
                "confidence": classification["confidence"],
            }

            # If anomalous, run REAL Prolog diagnosis
            if classification["is_anomalous"]:
                diagnosis = diagnose_threat(features)
                packet_data.update({
                    "threat_type": diagnosis["threat_type"],
                    "risk_level": diagnosis["risk_level"],
                    "mitigation": diagnosis["mitigation"],
                })

                # Log to encrypted vault
                _log_threat_to_vault(packet_data)

            # Emit to frontend via WebSocket
            socketio.emit("packet_data", packet_data)

            # Randomised delay (0.3–1.5s) to look like real traffic
            delay = random.uniform(0.3, 1.5)
            # Faster bursts during attack sequences
            if is_attack and random.random() < 0.6:
                delay = random.uniform(0.1, 0.4)
            socketio.sleep(delay)

    except Exception as e:
        print(f"[ERROR] Live capture error: {e}")
        socketio.emit("capture_error", {"error": str(e)})

    finally:
        capture_active = False
        socketio.emit("capture_status", {"status": "stopped"})
        print("[INFO] Live capture thread exited.")


# ============================================================
# Threat Logging (Bridge to Secure Vault)
# ============================================================
def _log_threat_to_vault(threat_entry: dict):
    """
    Logs a threat incident to the encrypted SQLite vault.

    This function is called whenever Prolog flags a packet as
    anomalous. The incident data is encrypted with AES-256
    before being stored in the database.

    Args:
        threat_entry: Dict containing full threat diagnosis data.
    """
    try:
        # Import here to avoid circular dependency at startup
        from db_manager import insert_threat_log
        row_id = insert_threat_log(threat_entry)
        threat_entry["id"] = row_id
        return row_id
    except ImportError:
        # db_manager not yet created (Phase 3)
        print(f"[LOG] Threat detected: {threat_entry.get('threat_type', 'unknown')} "
              f"from {threat_entry.get('src_ip', '?')} "
              f"(Risk: {threat_entry.get('risk_level', '?')})")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to log threat to vault: {e}")
        return None


# ============================================================
# REST API: Threat Logs
# ============================================================
@app.route("/logs", methods=["GET"])
def get_threat_logs():
    """
    Retrieves all threat logs from the encrypted vault.
    Decrypts each entry before returning.

    Returns:
        JSON array of decrypted threat log entries.
    """
    try:
        from db_manager import get_all_logs
        logs = get_all_logs()
        return jsonify({"logs": logs})
    except ImportError:
        return jsonify({"logs": [], "message": "Vault not initialized."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# REST API: PDF Report Generation
# ============================================================
@app.route("/report/<int:log_id>", methods=["GET"])
def generate_report(log_id):
    """
    Generates a PDF or HTML incident report for a specific threat log entry.

    Args:
        log_id: Integer ID of the threat log entry.

    Returns:
        File download response.
    """
    try:
        from db_manager import get_log_by_id
        from report_generator import generate_pdf_report

        log_entry = get_log_by_id(log_id)
        if log_entry is None:
            return jsonify({"error": "Log entry not found."}), 404

        report_path = generate_pdf_report(log_entry)
        _, ext = os.path.splitext(report_path)
        download_name = f"incident_report_{log_id}{ext}"
        mimetype = "application/pdf" if ext.lower() == ".pdf" else "text/html"

        return send_file(
            report_path,
            as_attachment=True,
            download_name=download_name,
            mimetype=mimetype
        )

    except ImportError:
        return jsonify({"error": "Report generator not available."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# REST API: System Status
# ============================================================
@app.route("/status", methods=["GET"])
def system_status():
    """
    Returns the current system status including component
    availability and readiness flags.

    Returns:
        JSON object with component status flags.
    """
    return jsonify({
        "ml_model_loaded": ml_pipeline is not None,
        "prolog_ready": prolog_engine is not None,
        "pyshark_available": PYSHARK_AVAILABLE,
        "capture_active": capture_active,
        "timestamp": datetime.now().isoformat(),
    })


# ============================================================
# REST API: Network Interfaces
# ============================================================
@app.route("/interfaces", methods=["GET"])
def get_interfaces():
    """
    Retrieves the list of available network interfaces with friendly names
    by executing tshark -D.
    """
    import subprocess
    import re

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    if not os.path.exists(tshark_path):
        tshark_path = "tshark"  # fallback

    try:
        # Run tshark -D to get list of network interfaces
        # Timeout after 3 seconds in case of hang
        result = subprocess.run(
            [tshark_path, "-D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=True
        )
        output = result.stdout
        interfaces = []
        for line in output.strip().split("\n"):
            line_str = line.strip()
            if not line_str:
                continue
            # Matches: "1. \Device\NPF_{...} (Wi-Fi)"
            match = re.match(r"^\d+\.\s+(\S+)\s+\((.+)\)$", line_str)
            if match:
                dev_path, friendly_name = match.groups()
                interfaces.append({
                    "name": dev_path,
                    "friendly": friendly_name
                })
            else:
                # Matches: "1. \Device\NPF_{...}"
                match2 = re.match(r"^\d+\.\s+(\S+)", line_str)
                if match2:
                    dev_path = match2.group(1)
                    interfaces.append({
                        "name": dev_path,
                        "friendly": dev_path
                    })
        return jsonify({"interfaces": interfaces})
    except Exception as e:
        print(f"[ERROR] Failed to query tshark interfaces: {e}")
        # Default fallback interfaces on Windows
        return jsonify({
            "error": str(e),
            "interfaces": [
                {"name": "Wi-Fi", "friendly": "Wi-Fi (Fallback)"},
                {"name": "Ethernet", "friendly": "Ethernet (Fallback)"}
            ]
        })


# ============================================================
# Main Page Routes
# ============================================================
@app.route("/")
def landing():
    """Serves the landing/login page."""
    return render_template("landing.html")


@app.route("/dashboard")
def dashboard():
    """Serves the main dashboard page."""
    return render_template("index.html")


# ============================================================
# Application Entry Point
# ============================================================
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" CYBER RISK & THREAT INTELLIGENCE SYSTEM")
    print(" Web Dashboard Server")
    print("=" * 60)

    # --- Initialize components ---
    print("\n[INIT] Loading ML model...")
    ml_pipeline = load_ml_model()

    print("\n[INIT] Initializing Prolog engine...")
    prolog_engine = init_prolog()

    # --- Ensure directories exist ---
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["REPORTS_FOLDER"], exist_ok=True)

    # --- Initialize database ---
    try:
        from db_manager import init_db
        init_db()
        print("[INIT] Secure vault database initialized.")
    except ImportError:
        print("[WARN] db_manager not available. Vault disabled.")

    print("\n" + "-" * 60)
    print(f" ML Model:    {'LOADED' if ml_pipeline else 'NOT LOADED'}")
    print(f" Prolog:      {'READY' if prolog_engine else 'FALLBACK MODE'}")
    print(f" Pyshark:     {'AVAILABLE' if PYSHARK_AVAILABLE else 'UNAVAILABLE'}")
    print("-" * 60)

    print("\n[START] Launching server at http://127.0.0.1:5005")
    print("[START] Press Ctrl+C to stop.\n")

    socketio.run(app, host="0.0.0.0", port=5005, debug=True, use_reloader=False)

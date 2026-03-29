import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')

print("="*50)
print(" RAKSHAK-AI : INTRUSION DETECTION SYSTEM INITIALIZING ")
print("="*50)

# ==========================================
# 1. SYNTHETIC NETWORK TRAFFIC GENERATION
# Simulating a corporate network with benign and malicious packets
# ==========================================
def generate_network_data(n_samples=5000):
    np.random.seed(42)
    
    # Normal Traffic (Benign) - 80% of data
    n_normal = int(n_samples * 0.8)
    normal_data = {
        'packet_size_bytes': np.random.normal(500, 100, n_normal),
        'connection_duration_sec': np.random.exponential(2, n_normal),
        'failed_login_attempts': np.random.poisson(0.1, n_normal),
        'file_entropy_score': np.random.uniform(2.0, 5.0, n_normal), # Low entropy = normal text/code
        'label': 0 # 0 means Safe
    }
    
    # Malicious Traffic (Known Malware/DDoS) - 20% of data
    n_malicious = n_samples - n_normal
    malicious_data = {
        'packet_size_bytes': np.random.normal(4000, 500, n_malicious), # Huge payloads
        'connection_duration_sec': np.random.exponential(15, n_malicious), # Long connections
        'failed_login_attempts': np.random.poisson(5.0, n_malicious), # Brute force attacks
        'file_entropy_score': np.random.uniform(7.0, 8.0, n_malicious), # High entropy = encrypted/packed malware
        'label': 1 # 1 means Malicious
    }
    
    df_normal = pd.DataFrame(normal_data)
    df_malicious = pd.DataFrame(malicious_data)
    
    # Combine and shuffle
    df = pd.concat([df_normal, df_malicious]).sample(frac=1).reset_index(drop=True)
    return df

print("\n[+] Capturing network packets and generating dataset...")
network_df = generate_network_data()

# ==========================================
# 2. DATA PREPROCESSING
# ==========================================
X = network_df.drop('label', axis=1)
y = network_df['label']

# Standardize the features so no single metric dominates the model
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# ==========================================
# 3. SUPERVISED LEARNING (Random Forest)
# For detecting *Known* Malware Signatures
# ==========================================
print("\n[+] Training Random Forest on Known Malware Signatures...")
rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
rf_classifier.fit(X_train, y_train)

y_pred_rf = rf_classifier.predict(X_test)
print(f"    -> Signature Detection Accuracy: {accuracy_score(y_test, y_pred_rf) * 100:.2f}%")

# ==========================================
# 4. UNSUPERVISED LEARNING (Isolation Forest)
# For detecting *Zero-Day* Attacks (Anomalies)
# ==========================================
print("\n[+] Training Isolation Forest for Zero-Day Anomaly Detection...")
# Train ONLY on normal data so it learns what a "healthy" network looks like
X_train_normal = X_train[y_train == 0] 

iso_forest = IsolationForest(contamination=0.05, random_state=42)
iso_forest.fit(X_train_normal)

print("    -> Baseline network behavior established.")

# ==========================================
# 5. LIVE INTRUSION DETECTION SIMULATION
# Testing the dual-engine on incoming packets
# ==========================================
def scan_live_packet(packet_data):
    """
    Takes a new network packet, scales it, and runs it through both models.
    """
    print("\n" + "-"*40)
    print(" 🚨 LIVE PACKET INTERCEPTED 🚨")
    print("-" + "-"*39)
    
    # Convert dict to dataframe and scale
    df_packet = pd.DataFrame([packet_data])
    packet_scaled = scaler.transform(df_packet)
    
    # 1. Check against known signatures
    rf_prediction = rf_classifier.predict(packet_scaled)[0]
    
    # 2. Check for zero-day anomalies (-1 means anomaly, 1 means normal)
    iso_prediction = iso_forest.predict(packet_scaled)[0]
    
    print(f"Packet Specs: Size: {packet_data['packet_size_bytes']}B | Entropy: {packet_data['file_entropy_score']}")
    
    if rf_prediction == 1:
        print(">> [ALERT] Signature Match! Known Malware Detected. CONNECTION BLOCKED.")
    elif iso_prediction == -1:
        print(">> [WARNING] Zero-Day Anomaly Detected! Unusual behavior. QUARANTINING FILE.")
    else:
        print(">> [SAFE] Traffic is benign. Connection allowed.")

# --- TEST 1: Normal Browsing Traffic ---
benign_packet = {
    'packet_size_bytes': 450,
    'connection_duration_sec': 1.2,
    'failed_login_attempts': 0,
    'file_entropy_score': 3.1 # Normal HTML/Text
}
scan_live_packet(benign_packet)

# --- TEST 2: Zero-Day Ransomware Attempt ---
zero_day_packet = {
    'packet_size_bytes': 6000, # Massive data dump
    'connection_duration_sec': 0.5,
    'failed_login_attempts': 12, # Brute force SSH
    'file_entropy_score': 7.9 # Highly encrypted payload
}
scan_live_packet(zero_day_packet)

print("\n" + "="*50)
print(" SYSTEM SECURE. MONITORING CONTINUES... ")
print("="*50)
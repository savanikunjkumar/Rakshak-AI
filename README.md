# 🛡️ Rakshak-AI: Zero-Day Malware & Intrusion Detection System

**Course:** Fundamentals of AI and ML Evaluated Course Project (BYOP)  
**Author:** Savani Kunjkumar Arvindbhai  
**Registration Number:** 25BCE11382  
**Date:** March 2026  

---

## 📌 Project Overview
Rakshak-AI is an intelligent, dual-engine Intrusion Detection System (IDS) built to secure networks against both known malware signatures and undocumented "Zero-Day" cyber attacks. Moving beyond traditional firewall limitations, this system utilizes a machine learning pipeline to analyze network packet behavior and file entropy in real-time, autonomously quarantining malicious payloads before they can execute.

## ⚙️ Architecture & Machine Learning Models
The system operates using a hybrid ensemble approach to maximize detection accuracy while minimizing false positives:

1. **Supervised Learning (Random Forest Classifier):** Trained on established threat data to detect known malware signatures, brute-force SSH attempts, and standard DDoS packet floods with high precision.
2. **Unsupervised Learning (Isolation Forest):** Acts as the Zero-Day defensive layer. By learning the "normal" baseline behavior of the network, it flags anomalous traffic—such as massive data exfiltration or heavily encrypted ransomware payloads—even if the virus has never been seen before.

## 🛠️ Technology Stack
* **Language:** Python 3.x
* **Data Processing:** Pandas, NumPy
* **Machine Learning:** Scikit-Learn (`RandomForestClassifier`, `IsolationForest`, `StandardScaler`)
* **Environment:** Compatible with standard terminal/command-line execution.

## 🚀 How to Run the Project (Evaluation Guide)

**Step 1: Install Dependencies** Ensure Python is installed on your system, then install the required machine learning libraries:
`pip install pandas numpy scikit-learn`

**Step 2: Execute the Core Engine** Run the main Python script from your terminal:
`python rakshak_ai_core.py`

**Step 3: Understanding the Output** Upon execution, the script will automatically:
1. Generate a simulated corporate network dataset (benign + malicious traffic).
2. Train both the Random Forest and Isolation Forest models.
3. Output the accuracy scores for signature detection.
4. Run a **Live Intrusion Simulation** demonstrating how the system handles a normal browsing packet versus a Zero-Day ransomware packet. 

## 📊 Core Features Extracted
The AI evaluates traffic based on the following engineered features:
* `packet_size_bytes`: Identifies abnormal data dumps.
* `connection_duration_sec`: Flags prolonged unauthorized server access.
* `failed_login_attempts`: Detects automated brute-force attacks.
* `file_entropy_score`: Measures code randomness to catch packed or encrypted malware executables.

---
*Developed for the BYOP Capstone Activity - VIT*

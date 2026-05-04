# PacketGuardian
An LLM-based Automated Threat Analysis and Forensic Framework
---

## 🚀 Key Features

* **Multi-Agent Orchestration**: Seamless integration of traffic parsing, threat intelligence mapping, and AI-driven reasoning.
* **Chain-of-Thought (CoT) Reasoning**: Empowers local LLMs (Llama 3 via Ollama) to perform expert-level security analysis.
* **Neural-Symbolic Verification**: A post-processing engine that cross-references LLM claims with raw forensic artifacts to eliminate AI hallucinations.
* **MITRE ATT&CK Mapping**: Automatically correlates detected behaviors with industry-standard TTPs (e.g., T1021, T1059).
* **Privacy-First Design**: Processes sensitive network data locally using Ollama, ensuring no traffic data leaves the secure environment.

---

## 🏗️ System Architecture



The framework consists of three core components:

1.  **Parser Agent (`detector.py`)**: Handles binary PCAP parsing and lightweight feature extraction (TCP/UDP, HTTP/TLS, and payload strings).
2.  **Researcher Agent (`researcher_agent.py`)**: Maps extracted features to the **MITRE ATT&CK** database and assesses protocol-specific risks.
3.  **Analyst Agent (`analyst_agent.py`)**: Performs high-level reasoning, generates forensic reports in Markdown, and executes the **Hallucination Verification** algorithm.

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.8+
* [Ollama](https://ollama.com/) (Running Llama 3)
* Scapy (`pip install scapy`)

### Environment Setup
1.  **Install dependencies**:
    ```bash
    pip install requests scapy
    ```
2.  **Start Ollama**:
    ```bash
    ollama run llama3
    ```

---

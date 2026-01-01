# Threat Hunter (Community / Demo Version)

Threat Hunter is a Python-based security tool designed to demonstrate malware detection capabilities using YARA rules. This repository serves as a **public showcase** and a feature-limited version of the full Threat Hunter ecosystem.

> [!NOTE]
> This is a **Showcase/Demo** version. The full Professional edition—featuring automated CI/CD pipelines, deep analysis engines, and FastAPI integration with a centralized web dashboard—is maintained in a private repository.

## 🚀 Features
- **YARA Integration:** Scan files and directories using industry-standard YARA signatures.
- **Structured Reporting:** Automatically generate scan results in CSV and JSON formats.
- **Batch Processing:** Consolidate multiple scan reports using the `mass_reporter.py` utility.

## 🛠️ Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/egemenguney/threat_hunter.git
   ```

2. Install the necessary dependencies:
    ```bash
    pip install -r requirements.txt

    ```


## 💻 Usage

### Basic Scan

Perform a scan on a specific path using a YARA rule file:

```bash
python threat_hunter.py <target_directory> rules.yar

```

### Batch Reporting

Merge existing reports into a single consolidated view:

```bash
python mass_reporter.py

```

## 📂 Project Structure

* `threat_hunter.py`: Core scanning logic.
* `rules.yar`: Sample YARA rule definitions.
* `mass_reporter.py`: Utility for aggregating scan results.
* `detected_repos.csv/json`: Sample output formats.

---

## 🔒 License & Copyright

**Copyright (c) 2025 Egemen Güney KOÇ | https://www.egemenguney.net | All rights reserved.**

This software is provided for **demonstration and educational purposes only**.

* **No Permission:** You may not copy, modify, redistribute, or use this code for commercial purposes.
* **Pro Version:** If you are interested in the full version (Pipeline integration, FastAPI backend, and Web Dashboard), please contact me directly.

---

**Contact:** contact@egemenguney.net





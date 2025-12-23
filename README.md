# 🎯 Threat Hunter

**GitHub Malware Repo Scanner & Reporter**

Tek komutla GitHub'daki malware dağıtan repo'ları tespit et, kategorize et ve raporla.

## 🚀 Quick Start

```bash
# 1. İlk tarama (threat_hunter.py zaten çalıştıysa atla)
python threat_hunter.py

# 2. Pipeline çalıştır - TEK KOMUT, TÜM ANALİZ
python pipeline.py

# 3. Sonuçlar:
#    pipeline_output/FINAL_REPORT.md     → Detaylı rapor
#    pipeline_output/repos_to_report.json → Mass report için hazır
#    pipeline_output/clusters.json       → Tüm veriler
```

## 📊 Son Analiz Sonuçları (23 Aralık 2025)

| Metrik | Sayı |
|--------|------|
| **Toplam Repo** | 1,117 |
| **Malware Link** | 118 |
| **easylauncher.su** | 9 |
| **mediafire.com** | 102 |
| **github.io Pattern** | 78 |

### 🔴 En Tehlikeli Pattern: easylauncher.su
```
https://easylauncher.su/PSnzrH
```
- VirusTotal: **12/66 malicious** (Trojan.FakeGit)
- Yöntem: Badge resimlerinin içine gizlenmiş link
- 9 repo tespit edildi

## 📁 Dosya Yapısı

```
threat_hunter/
├── threat_hunter.py     # GitHub repo tarayıcı
├── pipeline.py          # ⭐ ANA SCRIPT - Tek komut, tüm analiz
├── mass_reporter.py     # GitHub abuse reporter
├── rate_limit_monitor.py # API limit checker
├── rules.yar            # YARA kuralları
│
├── detected_repos.json  # threat_hunter çıktısı (1,318 repo)
├── detected_repos.csv   # Excel için
│
└── pipeline_output/     # Pipeline çıktıları
    ├── FINAL_REPORT.md  # 📋 Detaylı analiz raporu
    ├── repos_to_report.json  # Mass report için 118 repo
    └── clusters.json    # Tüm cluster verileri
```

## 🔄 Pipeline Aşamaları

```
STAGE 1: Load Repos
    └─ detected_repos.json → HIGH severity filtrele

STAGE 2: Clustering
    └─ Her repo için:
       - github.io linki var mı?
       - index.html var mı?
       - script.js var mı?
       - .zip/.exe dosyası var mı?
       - easylauncher.su linki var mı?
       - Diğer malware domain'leri var mı?

STAGE 3: Deep Analysis
    └─ Kategorize edilmiş repo'lar için:
       - README raw içeriği → malware domain search
       - index.html raw içeriği → redirect/link search
       - script.js raw içeriği → gizli URL search
       - github.io source repo → dosya listesi

STAGE 4: Generate Reports
    └─ FINAL_REPORT.md
    └─ repos_to_report.json
    └─ clusters.json
```

## 🎯 Tespit Edilen Malware Domain'ler

| Domain | Repo Sayısı | Risk |
|--------|-------------|------|
| easylauncher.su | 9 | 🔴 CRITICAL |
| mediafire.com | 102 | 🟠 HIGH |
| gofile.io | 5 | 🟠 HIGH |
| sites.google.com/view | 2 | 🟡 MEDIUM |
| mega.nz | 1 | 🟡 MEDIUM |

## 📝 GitHub'a Raporlama

```bash
# Dry run (test)
python mass_reporter.py --input pipeline_output/repos_to_report.json --dry-run

# Gerçek rapor (dikkatli kullan!)
python mass_reporter.py --input pipeline_output/repos_to_report.json
```

## ⚙️ Kurulum

```bash
# 1. Clone
git clone https://github.com/egemenguney/threat_hunter.git
cd threat_hunter

# 2. Virtual environment
python -m venv venv_threat
.\venv_threat\Scripts\activate  # Windows
source venv_threat/bin/activate # Linux/Mac

# 3. Dependencies
pip install -r requirements.txt

# 4. GitHub Token (opsiyonel ama önerilir)
# .env.local dosyası oluştur:
GITHUB_TOKEN=ghp_xxxxxxxxxxxxx
```

## 🔧 Pipeline Parametreleri

```bash
# Tam pipeline (stage 1-4)
python pipeline.py

# Sadece deep analysis (önceki cluster'ları kullan)
python pipeline.py --stage 3

# Sadece rapor oluştur
python pipeline.py --stage 4
```

---

**Author:** Security Research  
**Last Update:** December 23, 2025


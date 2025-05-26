# Phishing Detection Proxy

A prototype for real-time detection and blocking of phishing websites using a combination of public threat intelligence APIs, heuristic filters, and AI-based content classification — designed as part of a bachelor’s thesis.

## Overview

This project aims to enhance web browsing security by detecting and blocking phishing websites **before** the user accesses them. It works as a local proxy server using [mitmproxy](https://mitmproxy.org/) and evaluates each visited site using:

-  **VirusTotal API** – Multiple AV engine assessments
-  **Google Safe Browsing API** – Reputation check
-  **OpenAI API** – Content and title classification using GPT
-  **Heuristic rules** – File type filtering and URL cleaning

The proxy modifies traffic on the fly and blocks pages based on a consensus between the different detection engines.

## Features

-  Transparent and local proxy-based detection
-  Evaluation of web content (HTML + title)
-  AI-based phishing classification
-  Fusion of multi-engine threat intelligence
-  Reduction of false positives via custom scoring logic

## Requirements

- Python 3.8+ (tested with Python 3.11.9)
- Kali Linux (or any Unix-based OS; tested under Kali VM)
- A browser configured to use a local HTTP(S) proxy (127.0.0.1:8080)
- mitmproxy (tested with mitmproxy 10.2.3)
- VirusTotal API key --> https://docs.virustotal.com/docs/api-overview
- Google Safe Browsing API key --> https://developers.google.com/safe-browsing/v4/get-started#3.-set-up-an-api-key
- OpenAI API key --> https://platform.openai.com/api-keys

## Limitations

- API rate limits apply (especially for free-tier keys)
- Heavy resource calls (e.g. Google or YouTube pages) may result in false positives due to multiple domains/scripts
- SSL interception warnings might appear unless mitmproxy CA is trusted
- The OpenAI model is not specifically trained for phishing detection, so errors may occur

## Installation

1. **Clone the repository or download the script `phishingDetector.py` directly**  
   ```bash
   git clone https://github.com/BoyanOgnyanov/smart-phishing-detector.git
   ```
   OR
   ```bash
   wget https://github.com/BoyanOgnyanov/smart-phishing-detector/blob/main/phishingDetector.py
   ```

3. **Install the required dependencies**  
   Make sure you have Python 3.8+ installed, then install all required packages:

   ```bash
   pip install requests beautifulsoup4 openai
   ```
4. **Add your API-Keys in the ``phishingDetector.py``**
   
5. **Configure your browser to use a proxy**
   127.0.0.1(or localhost):8080

6. **Run the script using ``mitmproxy``**
   ```bash
   mitmproxy -s phishingDetector.py
   ```
7. **Open your browser and start surfing**


## Contact
- For questions or academic references, feel free to contact the author via GitHub.

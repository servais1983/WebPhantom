![image](webphantom.png)


# WebPhantom

WebPhantom is a web penetration testing CLI that provides reconnaissance, vulnerability scanning, local LLM-assisted analysis, and report generation.

## Features

- Recognition: collect basic target information
- Vulnerability scanning: detect common issues (XSS, SQLi, LFI)
- Advanced scanning: CSRF, SSRF, XXE, IDOR, SSTI (heuristics)
- Local AI analysis: Ollama API by default; automatic fallback to llama.cpp (GGUF)
- Report generation: HTML and PDF
- Authentication helpers: Basic, form, JWT; simple user store
- Payload generator: predefined payloads, transforms, and custom sets
- YAML scenario runner: orchestrate steps (recon, scan, ai, payload, report, etc.)
- IP scanning: wrappers for common external tools (Linux-oriented)

## Requirements

- Python 3.8+
- pip
- For AI via Ollama: a running Ollama server and a compatible model (e.g., llama3.1)
- Optional fallback: local disk space to store a GGUF model for llama.cpp

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Optional tools for IP scanning can be installed with:
```bash
python webphantom.py install-tools
```

## Local AI analysis (Ollama first)

1) Install and start Ollama, then pull a model (example: llama3.1):
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1
```

2) Run AI analysis on a target URL:
```bash
python webphantom.py ai https://example.com
```

3) Use AI in a YAML scenario (Ollama listens on http://localhost:11434):
```yaml
target: https://example.com
steps:
  - type: recon
  - type: scan
  - type: ai
    options:
      provider: ollama
      model: llama3.1
      temperature: 0.2
```

If Ollama is not available, WebPhantom will automatically try a llama.cpp fallback and may download a GGUF model as needed.

## Basic usage

```bash
# Recon and basic scan
python webphantom.py recon https://example.com
python webphantom.py scan https://example.com

# Run a basic scenario
python webphantom.py run scripts/basic_web_test.yaml --target https://example.com
```

Example `scripts/basic_web_test.yaml`:
```yaml
name: Basic web analysis
target: https://example.com
steps:
  - type: recon
  - type: scan
  - type: ai
```

## Payload generator

Generate payloads from predefined categories and optional transforms. From a YAML step:
```yaml
steps:
  - type: payload
    options:
      categories: ["xss", "sqli"]
      transformations: ["url", "html", "base64"]
```

## Reports

Generate HTML or PDF reports. Minimal example (YAML step):
```yaml
steps:
  - type: report
    options:
      format: html
```
If no aggregated results are provided, a basic report is generated.

## IP scanning (optional)

Linux-oriented wrappers for tools like Nmap, Nikto, TestSSL, etc. Root privileges may be required.
```bash
python webphantom.py ip-scan 192.168.1.0/24 --tools nmap nikto testssl
```

## Troubleshooting

- Import warnings (e.g., nltk, requests, tqdm, llama-cpp-python) usually mean dependencies are not installed in the active environment. Activate your venv and run `pip install -r requirements.txt`.
- On Windows, Ollama is typically run via WSL2 or a native installer. Ensure the API is reachable on http://localhost:11434.
- If llama.cpp fallback downloads a model, ensure sufficient disk space under `~/.webphantom/models`.

## License

MIT

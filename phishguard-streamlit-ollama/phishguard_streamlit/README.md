# PhishGuard AI — Streamlit + Ollama

A simplified, self-contained version of the uploaded PhishGuard AI project. It replaces the original React + Node + Flask + MongoDB stack with a single Streamlit application.

## Features

- Website / URL phishing screening
- HTTPS/TLS and DNS checks
- Redirect detection
- Suspicious URL / lookalike / punycode heuristics
- HTML title, login/password form and sensitive-data keyword checks
- Basic suspicious JavaScript pattern checks
- Email and SMS/chat phishing-language analysis
- Local Ollama explanation layer
- Scan history kept in the current Streamlit session
- No cloud AI API key required

> This is a defensive screening tool, not a guarantee that a website is safe. Never enter passwords, OTPs, card numbers or other secrets into suspicious sites.

## 1. Install Python

Use Python 3.10+ (3.11 or 3.12 recommended).

Check:

```bash
python --version
```

## 2. Create and activate a virtual environment

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

### Windows CMD

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Install Ollama

Install Ollama for your operating system, then open a new terminal.

Check:

```bash
ollama --version
```

Download a model, for example:

```bash
ollama pull llama3.2
```

Start Ollama if it is not already running:

```bash
ollama serve
```

The default local API is `http://127.0.0.1:11434`.

## 5. Start PhishGuard

Open a second terminal in this folder, activate the virtual environment, and run:

```bash
python -m streamlit run app.py
```

Or on Windows simply double-click `run.bat` after installing the dependencies.

Streamlit will print a local address, normally:

```text
http://localhost:8501
```

Open that address in your browser.

## 6. Configure Ollama

The left sidebar contains:

- **Ollama model** — defaults to `llama3.2`
- **Ollama URL** — defaults to `http://127.0.0.1:11434`

If you use another model, first pull it, for example:

```bash
ollama pull llama3.1
```

Then change the model name in the sidebar.

## How the system works

1. You submit a URL, email or message.
2. The local Python analyzer extracts security indicators.
3. A risk score and classification are calculated locally.
4. If Ollama is running, the result is sent to your local Ollama server for a human-readable explanation.
5. The report shows evidence and recommended safe actions.

### Important architecture point

Ollama is used as the **AI explanation layer**, not as the only phishing detector. This prevents a language model from being treated as a definitive security scanner. The deterministic checks produce the initial evidence and risk score.

## Troubleshooting

### `streamlit` is not recognized

Use:

```bash
python -m streamlit run app.py
```

### `ollama` connection failed

Make sure Ollama is running:

```bash
ollama serve
```

Then test the model:

```bash
ollama run llama3.2
```

### Ollama model not found

Pull it first:

```bash
ollama pull llama3.2
```

### URL fetch fails

Some websites block automated requests, require JavaScript, or use anti-bot protection. The scanner can still report the URL-level heuristics even when page content cannot be fetched.

## Project structure

```text
phishguard-streamlit/
├── app.py
├── analyzer.py
├── requirements.txt
├── run.bat
├── run.sh
├── README.md
└── .gitignore
```

# 🔍 Telegram Web Recon Bot

A private **Telegram-based recon assistant** for security researchers and bug bounty hunters.  
It automates common recon tasks like subdomain enum, alive host detection, port scanning, URL collection, and vulnerability scanning – right from Telegram.

> ⚠️ **Disclaimer:** This tool is for **authorized security testing only**.  
> Do **not** use it on systems you do not own or have explicit permission to test.

---

## ✨ Features

- 🧭 **Subdomain Enumeration** – via `subfinder`
- 🌐 **Alive Host Detection** – via `httpx`
- 🔌 **Port Scanning** – via `naabu` (top ports)
- 🌍 **URL Discovery** – via `gau` (raw + parameterized URLs)
- ⚠️ **Vulnerability Scanning** – via `nuclei` (full template support or configurable)
- 🔐 **Private Access** – only whitelisted Telegram user IDs can use the bot

---

## 🧱 Tech Stack

- **Language:** Python 3  
- **Bot Framework:** `python-telegram-bot`  
- **Tools:**  
  - `subfinder`  
  - `httpx`  
  - `naabu`  
  - `gau`  
  - `nuclei`

---

## 📦 Commands Overview

All commands are Telegram commands you send:

- `/start` – Show help / available commands  
- `/scan example.com` – Subdomain enumeration (subfinder)  
- `/httpx example.com` – Alive hosts + status code, title, tech, IP  
- `/ports example.com` – Port scan (top 100 ports via naabu)  
- `/urls example.com` – Raw URLs + URLs with parameters  
- `/nuclei example.com` – Nuclei scan against alive hosts  

---

## 🛠 Installation

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/telegram-recon-bot.git
cd telegram-recon-bot
```
### 2. Create & activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```
### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```
### 🔧 Install External Tools

```bash
sudo apt update
sudo apt install -y subfinder httpx-toolkit naabu nuclei
```
### Update Nuclei template

```bash
nuclei -update-templates
```
### Install gau (GetAllUrls)

```bash
sudo apt install -y golang-go
go install github.com/lc/gau/v2/cmd/gau@latest
```
### Add Go bin to PATH

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```
## 🔑 Configuration
### 1. Bot Token

Create a bot using @BotFather on Telegram
 and get your token.

 ### 2. Paste the bot token in the code "bot.py"

 ```bash
export TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
```

 ### 3. Restrict bot access

 ```bash
ALLOWED_USER_IDS = {
    123456789,  # your Telegram user ID
}
```
Get your ID from: @userinfobot

### ▶️ Usage

Run the bot:

```bash
source venv/bin/activate
python bot.py
```
Then in Telegram:
```bash
/scan example.com
/httpx example.com
/ports example.com
/urls example.com
/nuclei example.com
```
## ⚠️ Legal / Ethical Use

This project is intended ONLY for:

Learning

Authorized penetration testing

Bug bounty programs where permission is granted

You are solely responsible for using this tool legally.
The author is not liable for any misuse or damage.

## 🤝 Contributing

Contributions are welcome!

You can:

Open issues

Suggest features

Submit pull requests

Ideas for improvements:

/fullscan command (runs all modules)

Auto-report generation (Markdown / PDF)

Credit-based usage system

Docker setup

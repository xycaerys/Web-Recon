import re
import subprocess
from typing import List

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# =========================-
# CONFIG
# =========================-

BOT_TOKEN = "YOUR_TOKEN_HERE"  # <-- put your bot token from BotFather here

# Only these Telegram user IDs can use the bot
ALLOWED_USER_IDS = {
    00000000,  # your Telegram user ID
}

# External tools (binaries must be installed and in PATH)
SUBFINDER_BIN = "subfinder"
HTTPX_BIN = "/usr/local/bin/pdhttpx"
NAABU_BIN = "naabu"
GAU_BIN = "gau"
NUCLEI_BIN = "nuclei"


# ==========================
# HELPERS
# ==========================

def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$"
    return re.match(pattern, domain) is not None


def chunk_text(lines: List[str], max_chars: int = 3500) -> List[str]:
    """
    Split a list of lines into chunks that fit within Telegram's message limit.
    """
    chunks = []
    current = ""
    for line in lines:
        line_with_nl = line + "\n"
        if len(current) + len(line_with_nl) > max_chars:
            chunks.append(current)
            current = line_with_nl
        else:
            current += line_with_nl
    if current:
        chunks.append(current)
    return chunks


def run_subfinder(domain: str) -> List[str]:
    """
    Run subfinder on a domain and return list of subdomains.
    """
    try:
        result = subprocess.run(
            [SUBFINDER_BIN, "-silent", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise RuntimeError("subfinder is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("subfinder timed out.")

    if result.returncode not in (0, 1):
        raise RuntimeError(f"subfinder error: {result.stderr.strip()}")

    subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return sorted(set(subs))


def run_httpx(domains: List[str]) -> List[str]:
    """
    Run httpx on a list of domains and return processed results (one line per host).
    """
    if not domains:
        return []

    try:
        process = subprocess.Popen(
            [
                HTTPX_BIN,
                "-title",
                "-status-code",
                "-tech-detect",
                "-ip",
                "-silent",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        input_data = "\n".join(domains) + "\n"
        stdout, stderr = process.communicate(input_data, timeout=600)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"httpx error: {stderr.strip()}")

        results = [line.strip() for line in stdout.splitlines() if line.strip()]
        return results

    except FileNotFoundError:
        raise RuntimeError("httpx is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("httpx timed out.")


def run_naabu(domain: str) -> List[str]:
    """
    Run naabu port scan on a domain (top 100 ports).
    """
    try:
        result = subprocess.run(
            [NAABU_BIN, "-silent", "-top-ports", "100", "-host", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise RuntimeError("naabu is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("naabu timed out.")

    if result.returncode not in (0, 1):
        raise RuntimeError(f"naabu error: {result.stderr.strip()}")

    ports = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return ports


def run_gau(domain: str) -> List[str]:
    """
    Run gau (GetAllUrls) on a domain and return list of URLs.
    """
    try:
        result = subprocess.run(
            [GAU_BIN, domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        raise RuntimeError("gau is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("gau timed out.")

    if result.returncode not in (0, 1):
        raise RuntimeError(f"gau error: {result.stderr.strip()}")

    urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
    return sorted(set(urls))


def filter_urls(urls: List[str]) -> List[str]:
    """
    Return only URLs with parameters (e.g. ?id=1), good for SQLi/XSS.
    """
    filtered = []
    for u in urls:
        if "?" in u:
            filtered.append(u)
    return filtered


def run_nuclei(urls: List[str]) -> List[str]:
    """
    Run nuclei with full templates against a list of URLs.
    """
    if not urls:
        return []

    try:
        process = subprocess.Popen(
            [NUCLEI_BIN, "-silent", "-nc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        input_data = "\n".join(urls) + "\n"
        stdout, stderr = process.communicate(input_data, timeout=1800)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"nuclei error: {stderr.strip()}")

        findings = [line.strip() for line in stdout.splitlines() if line.strip()]
        return sorted(set(findings))

    except FileNotFoundError:
        raise RuntimeError("nuclei is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("nuclei timed out (took too long).")


# ==========================
# HANDLERS
# ==========================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USER_IDS:
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return

    await update.message.reply_text(
        "🔎 *Recon Bot Ready*\n\n"
        "Available commands:\n"
        "  `/scan example.com`   – Subdomains (subfinder)\n"
        "  `/httpx example.com`  – Alive hosts + info (httpx)\n"
        "  `/ports example.com`  – Open ports (naabu)\n"
        "  `/urls example.com`   – RAW + filtered URLs (gau)\n"
        "  `/nuclei example.com` – Full template vuln scan (nuclei)\n\n"
        "⚠ Use only on targets you own or have permission to test.",
        parse_mode="Markdown",
    )


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USER_IDS:
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: `/scan example.com`", parse_mode="Markdown")
        return

    domain = context.args[0].lower().strip()

    if not is_valid_domain(domain):
        await update.message.reply_text(
            "❌ Please provide a valid domain, e.g. `example.com`",
            parse_mode="Markdown",
        )
        return

    msg = await update.message.reply_text(
        f"⏳ Scanning *{domain}* for subdomains...",
        parse_mode="Markdown",
    )

    try:
        subdomains = run_subfinder(domain)
    except RuntimeError as e:
        await msg.edit_text(f"❌ Error during scan: `{str(e)}`", parse_mode="Markdown")
        return

    if not subdomains:
        await msg.edit_text(
            f"✅ Scan complete.\nNo subdomains found for *{domain}*.",
            parse_mode="Markdown",
        )
        return

    count = len(subdomains)

    await msg.edit_text(
        f"✅ Scan complete for *{domain}*.\n"
        f"Found *{count}* subdomains.\n"
        f"Sending results...",
        parse_mode="Markdown",
    )

    chunks = chunk_text(subdomains)
    for i, chunk in enumerate(chunks, start=1):
        await update.message.reply_text(
            f"📄 Subdomains ({i}/{len(chunks)}):\n\n{chunk}"
        )


async def httpx_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USER_IDS:
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /httpx example.com")
        return

    domain = context.args[0].strip().lower()
    if not is_valid_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    msg = await update.message.reply_text(
        f"⏳ Running httpx scan on *{domain}*...",
        parse_mode="Markdown",
    )

    # Step 1: Get subdomains
    try:
        subs = run_subfinder(domain)
    except Exception as e:
        await msg.edit_text(f"❌ Subfinder error: `{str(e)}`", parse_mode="Markdown")
        return

    if not subs:
        await msg.edit_text("No subdomains found.", parse_mode="Markdown")
        return

    # Step 2: Run HTTPX
    try:
        results = run_httpx(subs)
    except Exception as e:
        await msg.edit_text(f"❌ httpx error: `{str(e)}`", parse_mode="Markdown")
        return

    if not results:
        await msg.edit_text("❌ No alive hosts found.", parse_mode="Markdown")
        return

    await msg.edit_text(
        f"✅ HTTPX complete. Found *{len(results)}* alive hosts.\nSending results...",
        parse_mode="Markdown",
    )

    chunks = chunk_text(results)
    for i, chunk in enumerate(chunks, start=1):
        await update.message.reply_text(
            f"📡 Alive hosts ({i}/{len(chunks)}):\n\n{chunk}"
        )


async def ports_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USER_IDS:
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /ports example.com")
        return

    domain = context.args[0].strip().lower()
    if not is_valid_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    msg = await update.message.reply_text(
        f"⏳ Running port scan on *{domain}*...",
        parse_mode="Markdown",
    )

    try:
        ports = run_naabu(domain)
    except Exception as e:
        await msg.edit_text(f"❌ Naabu error: `{str(e)}`", parse_mode="Markdown")
        return

    if not ports:
        await msg.edit_text(
            f"No open ports found for *{domain}*.",
            parse_mode="Markdown",
        )
        return

    await msg.edit_text(
        f"✅ Port scan complete.\nFound *{len(ports)}* open ports.\nSending results...",
        parse_mode="Markdown",
    )

    chunks = chunk_text(ports)
    for i, chunk in enumerate(chunks, start=1):
        await update.message.reply_text(
            f"🔌 Open Ports ({i}/{len(chunks)}):\n\n{chunk}"
        )


async def urls_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USER_IDS:
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /urls example.com")
        return

    domain = context.args[0].strip().lower()
    if not is_valid_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    msg = await update.message.reply_text(
        f"⏳ Finding URLs for *{domain}*...\n(This may take some time)",
        parse_mode="Markdown",
    )

    try:
        urls = run_gau(domain)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{str(e)}`", parse_mode="Markdown")
        return

    if not urls:
        await msg.edit_text("❌ No URLs found.", parse_mode="Markdown")
        return

    filtered = filter_urls(urls)

    await msg.edit_text(
        f"✅ URL Scan Complete for *{domain}*\n"
        f"Total URLs: *{len(urls)}*\n"
        f"Filtered (with params): *{len(filtered)}*",
        parse_mode="Markdown",
    )

    # RAW URLs
    raw_chunks = chunk_text(urls)
    for i, chunk in enumerate(raw_chunks, 1):
        await update.message.reply_text(
            f"📄 RAW URLs ({i}/{len(raw_chunks)}):\n\n{chunk}"
        )

    # Filtered URLs
    if filtered:
        filt_chunks = chunk_text(filtered)
        for i, chunk in enumerate(filt_chunks, 1):
            await update.message.reply_text(
                f"🎯 Filtered URLs ({i}/{len(filt_chunks)}):\n\n{chunk}"
            )


async def nuclei_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USER_IDS:
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /nuclei example.com")
        return

    domain = context.args[0].strip().lower()
    if not is_valid_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    msg = await update.message.reply_text(
        f"⏳ Running *full Nuclei scan* on *{domain}*...\n"
        f"➡ This can take several minutes.\n"
        f"➡ Using full template set.",
        parse_mode="Markdown",
    )

    # 1) Get subdomains
    try:
        subdomains = run_subfinder(domain)
    except Exception as e:
        await msg.edit_text(f"❌ Subfinder error: `{str(e)}`", parse_mode="Markdown")
        return

    if not subdomains:
        await msg.edit_text(
            f"✅ No subdomains found for *{domain}*. Nothing to scan.",
            parse_mode="Markdown",
        )
        return

    # 2) Get alive hosts via httpx
    try:
        httpx_results = run_httpx(subdomains)
    except Exception as e:
        await msg.edit_text(f"❌ httpx error: `{str(e)}`", parse_mode="Markdown")
        return

    urls = []
    for line in httpx_results:
        parts = line.split()
        if parts:
            urls.append(parts[0])

    if not urls:
        urls = [f"http://{domain}", f"https://{domain}"]

    await msg.edit_text(
        f"⏳ Subdomains: *{len(subdomains)}*\n"
        f"🌐 Alive targets for Nuclei: *{len(urls)}*\n"
        f"🚀 Starting Nuclei (full templates)...",
        parse_mode="Markdown",
    )

    # 3) Run Nuclei
    try:
        findings = run_nuclei(urls)
    except Exception as e:
        await msg.edit_text(f"❌ Nuclei error: `{str(e)}`", parse_mode="Markdown")
        return

    if not findings:
        await msg.edit_text(
            f"✅ Nuclei scan complete for *{domain}*.\n"
            f"No findings from templates.",
            parse_mode="Markdown",
        )
        return

    await msg.edit_text(
        f"✅ Nuclei scan complete for *{domain}*.\n"
        f"Total findings: *{len(findings)}*\n"
        f"Sending results in chunks...",
        parse_mode="Markdown",
    )

    chunks = chunk_text(findings)
    for i, chunk in enumerate(chunks, start=1):
        await update.message.reply_text(
            f"⚠️ Nuclei Findings ({i}/{len(chunks)}):\n\n{chunk}"
        )


async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "I don't recognize that command. Use `/start` to see available commands.",
        parse_mode="Markdown",
    )


# ==========================
# MAIN
# ==========================

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("httpx", httpx_cmd))
    app.add_handler(CommandHandler("ports", ports_cmd))
    app.add_handler(CommandHandler("urls", urls_cmd))
    app.add_handler(CommandHandler("nuclei", nuclei_cmd))

    app.add_handler(MessageHandler(filters.COMMAND, unknown))

    app.run_polling()


if __name__ == "__main__":
    main()

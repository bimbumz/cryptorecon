import os
import time
import threading
import requests
from flask import Flask
from telegram.ext import Updater, CommandHandler
from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum,
    Bip44, Bip49, Bip84, Bip44Coins, Bip49Coins, Bip84Coins, Bip44Changes
)
from datetime import datetime

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
SOLSCAN_API_KEY = os.getenv("SOLSCAN_API_KEY")
LOG_FILE = "scanned_results.log"
scanning = False

# Web server to keep Render Web Service alive
app = Flask(__name__)
@app.route("/")
def home():
    return "Bot is running!"

# Check balances
def check_btc(address):
    try:
        r = requests.get(f"https://blockstream.info/api/address/{address}")
        data = r.json()
        funded = data["chain_stats"]["funded_txo_sum"]
        spent = data["chain_stats"]["spent_txo_sum"]
        return (funded - spent) / 1e8
    except:
        return None

def check_eth(address):
    try:
        r = requests.get("https://api.etherscan.io/api", params={
            "module": "account", "action": "balance", "address": address,
            "tag": "latest", "apikey": ETHERSCAN_API_KEY
        })
        return int(r.json()["result"]) / 1e18
    except:
        return None

def check_sol(address):
    try:
        r = requests.get(f"https://pro-api.solscan.io/v2/account/{address}", headers={
            "accept": "application/json",
            "token": SOLSCAN_API_KEY
        })
        data = r.json()
        lamports = int(data["data"].get("lamports", 0))
        return lamports / 1e9
    except:
        return None

# Generate random BIP39 mnemonic
def generate_mnemonic(word_count):
    word_map = {
        12: Bip39WordsNum.WORDS_NUM_12,
        15: Bip39WordsNum.WORDS_NUM_15,
        18: Bip39WordsNum.WORDS_NUM_18,
        24: Bip39WordsNum.WORDS_NUM_24
    }
    return str(Bip39MnemonicGenerator().FromWordsNumber(word_map[word_count]))

# Derive addresses and check balances
def derive_and_check_all(mnemonic):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    results = []
    found_balance = False

    btc_paths = {
        "BIP44": Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN),
        "BIP49": Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN),
        "BIP84": Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN),
    }

    for label, wallet in btc_paths.items():
        acc = wallet.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
        for i in range(10):
            addr = acc.AddressIndex(i).PublicKey().ToAddress()
            balance = check_btc(addr)
            time.sleep(0.5)
            if balance and balance > 0:
                found_balance = True
                results.append(f"💰 BTC ({label}) [{addr}] = {balance:.8f} BTC")
            else:
                results.append(f"⭕ BTC ({label}) [{addr}] = 0 BTC")

    eth_wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    for i in range(10):
        addr = eth_wallet.AddressIndex(i).PublicKey().ToAddress()
        balance = check_eth(addr)
        time.sleep(0.5)
        if balance and balance > 0:
            found_balance = True
            results.append(f"💰 ETH [{addr}] = {balance:.6f} ETH")
        else:
            results.append(f"⭕ ETH [{addr}] = 0 ETH")

    sol_wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    for i in range(10):
        addr = sol_wallet.AddressIndex(i).PublicKey().ToAddress()
        balance = check_sol(addr)
        time.sleep(0.5)
        if balance and balance > 0:
            found_balance = True
            results.append(f"💰 SOL [{addr}] = {balance:.6f} SOL")
        else:
            results.append(f"⭕ SOL [{addr}] = 0 SOL")

    return results, found_balance

# Log to file
def log_scan(mnemonic, results):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] Mnemonic: {mnemonic}\n")
        for r in results:
            f.write(r + "\n")
        f.write("-" * 40 + "\n")

# Telegram bot handlers
def start(update, context):
    update.message.reply_text("👋 Use /scan <12|15|18|24> to scan once, or /startscan <12|15|18|24> for continuous scanning.")

def stopscan(update, context):
    global scanning
    scanning = False
    update.message.reply_text("🛑 Background scan stopped.")

def scan(update, context):
    try:
        count = int(context.args[0])
        mnemonic = generate_mnemonic(count)
        results, found = derive_and_check_all(mnemonic)
        log_scan(mnemonic, results)
        msg = "\n".join(results)
        update.message.reply_text(f"📋 *Scan Result:*\n\n{msg}\n\n🔑 *Mnemonic:* `{mnemonic}`", parse_mode="Markdown")
        if found:
            context.bot.send_message(chat_id=update.effective_chat.id, text=f"🚨 *BALANCE FOUND!*\n\n`{mnemonic}`", parse_mode="Markdown")
    except:
        update.message.reply_text("❌ Usage: /scan <12|15|18|24>")

def background_scan(context, word_count):
    global scanning
    while scanning:
        mnemonic = generate_mnemonic(word_count)
        results, found = derive_and_check_all(mnemonic)
        log_scan(mnemonic, results)
        if found:
            msg = "\n".join(results)
            context.bot.send_message(
                chat_id=context.job.context,
                text=f"🚨 *BALANCE FOUND!*\n\n{msg}\n\n🔑 `{mnemonic}`",
                parse_mode="Markdown"
            )

def startscan(update, context):
    global scanning
    try:
        count = int(context.args[0])
        if scanning:
            update.message.reply_text("⚠️ Scan already running.")
            return
        scanning = True
        update.message.reply_text("🚀 Background scan started.")
        threading.Thread(target=background_scan, args=(context, count), daemon=True).start()
    except:
        update.message.reply_text("❌ Usage: /startscan <12|15|18|24>")

def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dp = updater.dispatcher
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("scan", scan))
    dp.add_handler(CommandHandler("startscan", startscan))
    dp.add_handler(CommandHandler("stopscan", stopscan))
    threading.Thread(target=updater.start_polling, daemon=True).start()

if __name__ == "__main__":
    main()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

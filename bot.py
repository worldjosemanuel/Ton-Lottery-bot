import os
import sqlite3
import secrets
import asyncio
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple, Any, Dict

import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton
from aiogram.filters import Command
from dotenv import load_dotenv

from tonsdk.contract.wallet import WalletVersionEnum, Wallets
from tonsdk.crypto import mnemonic_new
from tonsdk.utils import to_nano, bytes_to_b64str

import re

from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.state import StatesGroup, State
from aiogram.fsm.context import FSMContext


DB_PATH = "raffle.db"
BOT_USERNAME = "CoinUSDT_Lottery_Bot"  # sin @


# ----------------------------
# Config
# ----------------------------
@dataclass
class Config:
    token: str
    admin_ids: List[int]
    ton_api_base: str
    ton_api_key: str


def load_config() -> Config:
    load_dotenv()

    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Falta BOT_TOKEN en .env")

    admin_raw = os.getenv("ADMIN_IDS", "").strip()
    admin_ids = [int(x.strip()) for x in admin_raw.split(",") if x.strip().isdigit()]
    if not admin_ids:
        raise RuntimeError("Falta ADMIN_IDS en .env (al menos uno)")

    ton_api_base = os.getenv("TON_API_BASE", "").strip().rstrip("/")
    if not ton_api_base:
        raise RuntimeError("Falta TON_API_BASE en .env (ej: https://toncenter.com/api/v2)")

    ton_api_key = os.getenv("TONCENTER_API_KEY", "").strip()
    if not ton_api_key:
        raise RuntimeError("Falta TONCENTER_API_KEY en .env")

    return Config(token=token, admin_ids=admin_ids, ton_api_base=ton_api_base, ton_api_key=ton_api_key)


# ----------------------------
# DB init + helpers
# ----------------------------
def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # Participantes / referrals
    cur.execute("""
        CREATE TABLE IF NOT EXISTS participants (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            referrer_id INTEGER,
            joined_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Wallets TON
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ton_wallets (
            user_id INTEGER PRIMARY KEY,
            mnemonic TEXT NOT NULL,
            address_raw TEXT NOT NULL,
            address_nb TEXT NOT NULL,
            balance_nano INTEGER NOT NULL DEFAULT 0,
            payout_address_raw TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Transacciones procesadas (depósitos)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ton_processed_tx (
            user_id INTEGER NOT NULL,
            tx_lt INTEGER NOT NULL,
            tx_hash TEXT NOT NULL,
            PRIMARY KEY (user_id, tx_lt, tx_hash)
        )
    """)

    # Retiros
    cur.execute("""
        CREATE TABLE IF NOT EXISTS withdrawals (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          to_address_raw TEXT NOT NULL,
          amount_nano INTEGER NOT NULL,
          status TEXT NOT NULL,           -- QUEUED, SENDING, SENT, FAILED, REFUNDED
          error TEXT,
          tx_hash TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status)")

    # --- Tablas para rifas ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS raffles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            total_numbers INTEGER NOT NULL,
            ticket_price_nano INTEGER NOT NULL,
            sold_tickets INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN, SOLD_OUT, PAID
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS raffle_prizes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raffle_id INTEGER NOT NULL,
            winning_number INTEGER NOT NULL,
            percent REAL NOT NULL,
            FOREIGN KEY(raffle_id) REFERENCES raffles(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS raffle_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raffle_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            number INTEGER NOT NULL,
            purchased_at TEXT DEFAULT (datetime('now')),
            UNIQUE(raffle_id, number),
            FOREIGN KEY(raffle_id) REFERENCES raffles(id)
        )
    """)

    con.commit()
    con.close()


def participant_exists(user_id: int) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM participants WHERE user_id=? LIMIT 1", (user_id,))
    row = cur.fetchone()
    con.close()
    return row is not None


def upsert_participant(
    user_id: int,
    username: Optional[str],
    first_name: Optional[str],
    referrer_id: Optional[int]
) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO participants (user_id, username, first_name, referrer_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            first_name=excluded.first_name,
            referrer_id=COALESCE(participants.referrer_id, excluded.referrer_id)
    """, (user_id, username, first_name, referrer_id))
    con.commit()
    con.close()


def remove_participant(user_id: int) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DELETE FROM participants WHERE user_id=?", (user_id,))
    deleted = cur.rowcount
    con.commit()
    con.close()
    return deleted > 0


def list_participants() -> List[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT user_id, username, first_name FROM participants ORDER BY joined_at ASC")
    rows = cur.fetchall()
    con.close()
    return rows


def pick_winner() -> Optional[tuple]:
    rows = list_participants()
    if not rows:
        return None
    idx = secrets.randbelow(len(rows))
    return rows[idx]


def get_wallet_row(user_id: int) -> Optional[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT user_id, mnemonic, address_raw, address_nb, balance_nano, payout_address_raw
        FROM ton_wallets WHERE user_id=?
    """, (user_id,))
    row = cur.fetchone()
    con.close()
    return row


def create_wallet_row(user_id: int, mnemonic: str, address_raw: str, address_nb: str) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO ton_wallets (user_id, mnemonic, address_raw, address_nb)
        VALUES (?, ?, ?, ?)
    """, (user_id, mnemonic, address_raw, address_nb))
    con.commit()
    con.close()


def add_balance_nano(user_id: int, delta: int) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("UPDATE ton_wallets SET balance_nano = balance_nano + ? WHERE user_id=?", (delta, user_id))
    con.commit()
    con.close()


def set_payout_address(user_id: int, payout_raw: str) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("UPDATE ton_wallets SET payout_address_raw=? WHERE user_id=?", (payout_raw, user_id))
    con.commit()
    con.close()


def list_all_wallets() -> List[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT user_id, address_raw FROM ton_wallets")
    rows = cur.fetchall()
    con.close()
    return rows


def mark_tx_processed(user_id: int, tx_lt: int, tx_hash: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute("""
            INSERT INTO ton_processed_tx (user_id, tx_lt, tx_hash)
            VALUES (?, ?, ?)
        """, (user_id, tx_lt, tx_hash))
        con.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        con.close()


# ---- withdrawals DB helpers
def create_withdrawal(user_id: int, to_address_raw: str, amount_nano: int) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO withdrawals (user_id, to_address_raw, amount_nano, status)
        VALUES (?, ?, ?, 'QUEUED')
    """, (user_id, to_address_raw, amount_nano))
    wid = cur.lastrowid
    con.commit()
    con.close()
    return int(wid)


def set_withdrawal_status(
    wid: int,
    status: str,
    error: Optional[str] = None,
    tx_hash: Optional[str] = None
) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        UPDATE withdrawals
        SET status=?,
            error=COALESCE(?, error),
            tx_hash=COALESCE(?, tx_hash),
            updated_at=datetime('now')
        WHERE id=?
    """, (status, error, tx_hash, wid))
    con.commit()
    con.close()


def fetch_next_withdrawal() -> Optional[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT id, user_id, to_address_raw, amount_nano
        FROM withdrawals
        WHERE status='QUEUED'
        ORDER BY id ASC
        LIMIT 1
    """)
    row = cur.fetchone()
    con.close()
    return row


def list_withdrawals(status: str = "QUEUED", limit: int = 20) -> List[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT id, user_id, to_address_raw, amount_nano, status, created_at, updated_at
        FROM withdrawals
        WHERE status=?
        ORDER BY id DESC
        LIMIT ?
    """, (status, limit))
    rows = cur.fetchall()
    con.close()
    return rows


# ----------------------------
# UI helpers
# ----------------------------
def main_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="👥 Referral"), KeyboardButton(text="➕ Add Balance")],
            [KeyboardButton(text="💰 My Balance"), KeyboardButton(text="🏆 Withdraw")],
            [KeyboardButton(text="🎫 Buy Ticket")],
        ],
        resize_keyboard=True
    )


def lotteries_keyboard(raffles: List[tuple]) -> ReplyKeyboardMarkup:
    rows = []
    for rid, name, total, sold, price_nano, status in raffles:
        label = f"🎯 {name} (ID {rid})"
        rows.append([KeyboardButton(text=label)])
    rows.append([KeyboardButton(text="⬅️ Atrás")])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)


def raffle_detail_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🎫 Buy Ticket Now")],
            [KeyboardButton(text="⬅️ Atrás")],
        ],
        resize_keyboard=True
    )


def is_admin(user_id: int, cfg: Config) -> bool:
    return user_id in cfg.admin_ids


def format_user(user_id: int, username: Optional[str], first_name: Optional[str]) -> str:
    if username:
        return f"@{username} (id:{user_id})"
    if first_name:
        return f"{first_name} (id:{user_id})"
    return f"id:{user_id}"


def parse_referrer_id_from_start(message_text: str, current_user_id: int) -> Optional[int]:
    if not message_text:
        return None
    parts = message_text.split(maxsplit=1)
    if len(parts) < 2:
        return None
    arg = parts[1].strip()
    if not arg.startswith("ref_"):
        return None
    raw = arg.replace("ref_", "", 1).strip()
    if not raw.isdigit():
        return None
    rid = int(raw)
    if rid == current_user_id:
        return None
    return rid


def to_url_safe_addr(s: str) -> str:
    return s.replace("/", "_").replace("+", "-")


# ----------------------------
# TON wallet generation per user (custodial)
# ----------------------------
def ensure_user_wallet(user_id: int) -> Tuple[str, str]:
    row = get_wallet_row(user_id)
    if row:
        return row[3], row[2]  # nb, raw

    version = getattr(WalletVersionEnum, "v4r2", WalletVersionEnum.v3r2)
    words = mnemonic_new()
    _, _, _, wallet = Wallets.from_mnemonics(words, version, 0)

    address_raw = wallet.address.to_string()
    address_nb = wallet.address.to_string(True, False, True)
    address_nb = to_url_safe_addr(address_nb)

    create_wallet_row(user_id, " ".join(words), address_raw, address_nb)
    return address_nb, address_raw


def wallet_from_mnemonic(mnemonic_str: str):
    version = getattr(WalletVersionEnum, "v4r2", WalletVersionEnum.v3r2)
    words = [w for w in mnemonic_str.split() if w]
    _, _, _, wallet = Wallets.from_mnemonics(words, version, 0)
    return wallet


# ----------------------------
# TON API calls
# ----------------------------
async def ton_get_transactions(cfg: Config, address: str, limit: int = 20) -> List[Dict[str, Any]]:
    url = f"{cfg.ton_api_base}/getTransactions"
    headers = {"X-API-Key": cfg.ton_api_key}
    params = {"address": address, "limit": str(limit)}
    async with aiohttp.ClientSession() as s:
        async with s.get(url, headers=headers, params=params, timeout=30) as r:
            data = await r.json()
            if not data.get("ok"):
                raise RuntimeError(str(data))
            return data.get("result") or []


async def ton_get_wallet_information(cfg: Config, address: str) -> Dict[str, Any]:
    url = f"{cfg.ton_api_base}/getWalletInformation"
    headers = {"X-API-Key": cfg.ton_api_key}
    params = {"address": address}
    async with aiohttp.ClientSession() as s:
        async with s.get(url, headers=headers, params=params, timeout=30) as r:
            data = await r.json()
            if not data.get("ok"):
                raise RuntimeError(str(data))
            return data.get("result") or {}


async def ton_send_boc(cfg: Config, boc_b64: str) -> Any:
    url = f"{cfg.ton_api_base}/sendBoc"
    headers = {"X-API-Key": cfg.ton_api_key, "Content-Type": "application/json"}
    payload = {"boc": boc_b64}
    async with aiohttp.ClientSession() as s:
        async with s.post(url, headers=headers, json=payload, timeout=30) as r:
            data = await r.json()
            if not data.get("ok"):
                raise RuntimeError(str(data))
            return data.get("result")


async def ton_detect_address(cfg: Config, address: str) -> Dict[str, Any]:
    url = f"{cfg.ton_api_base}/detectAddress"
    headers = {"X-API-Key": cfg.ton_api_key}
    params = {"address": address}
    async with aiohttp.ClientSession() as s:
        async with s.get(url, headers=headers, params=params, timeout=30) as r:
            data = await r.json()
            if not data.get("ok"):
                raise RuntimeError(str(data))
            return data.get("result") or {}


async def raw_to_nb_urlsafe(cfg: Config, raw_addr: str) -> str:
    try:
        info = await ton_detect_address(cfg, raw_addr)
        nb = (
            info.get("non_bounceable_url_safe")
            or info.get("non_bounceable")
            or info.get("non_bounceable_address")
            or info.get("address")
        )
        if not nb:
            return raw_addr
        return str(nb).replace("/", "_").replace("+", "-")
    except Exception:
        return raw_addr


# ----------------------------
# FSM: set_payout
# ----------------------------
class PayoutStates(StatesGroup):
    waiting_address = State()


def normalize_ton_address(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "").replace("\ufeff", "")
    t = "".join(t.split())
    return t


def looks_like_ton_address(addr: str) -> bool:
    if not addr:
        return False
    return bool(re.match(r"^(0:[0-9a-fA-F]{64}|EQ|UQ)[A-Za-z0-9\-_]{10,}$", addr))


# Regex enteros o 1 decimal
DECIMAL_1_RE = re.compile(r"^[0-9]+(\.[0-9])?$")

# Cooldown para Buy Ticket Now
LAST_SINGLE_BUY: Dict[int, float] = {}
# Rifa seleccionada por usuario
SELECTED_RAFFLE: Dict[int, int] = {}
# Menú actual
CURRENT_MENU: Dict[int, str] = {}


# ----------------------------
# Workers
# ----------------------------
async def deposits_worker(cfg: Config, bot: Bot) -> None:
    while True:
        try:
            wallets = list_all_wallets()
            for user_id, addr_raw in wallets:
                txs = await ton_get_transactions(cfg, addr_raw, limit=20)
                for tx in txs:
                    txid = tx.get("transaction_id") or {}
                    tx_lt = int(txid.get("lt") or 0)
                    tx_hash = str(txid.get("hash") or "")
                    if not tx_lt or not tx_hash:
                        continue

                    in_msg = tx.get("in_msg") or {}
                    destination = in_msg.get("destination")
                    value = in_msg.get("value")

                    if not destination or str(destination) != str(addr_raw):
                        continue

                    try:
                        value_nano = int(value)
                    except Exception:
                        continue
                    if value_nano <= 0:
                        continue

                    if not mark_tx_processed(user_id, tx_lt, tx_hash):
                        continue

                    add_balance_nano(user_id, value_nano)
                    await bot.send_message(
                        user_id,
                        f"✅ Depósito recibido: {value_nano / 1e9:.6f} TON\n"
                        "💰 Acreditado a tu saldo interno."
                    )

            await asyncio.sleep(10)
        except Exception as e:
            print("deposits_worker error:", e)
            await asyncio.sleep(10)


async def withdrawals_worker(cfg: Config, bot: Bot) -> None:
    while True:
        try:
            w = fetch_next_withdrawal()
            if not w:
                await asyncio.sleep(3)
                continue

            wid, user_id, to_raw, amount_nano = w
            set_withdrawal_status(wid, "SENDING")

            row = get_wallet_row(user_id)
            if not row:
                add_balance_nano(user_id, int(amount_nano))
                set_withdrawal_status(wid, "REFUNDED", error="No existe wallet del usuario")
                await bot.send_message(user_id, f"❌ Retiro falló (sin wallet) y fue reembolsado. ID: {wid}")
                continue

            mnemonic_str = row[1]
            user_addr_raw = row[2]

            try:
                info = await ton_get_wallet_information(cfg, user_addr_raw)
                seqno = int(info.get("seqno") or 0)

                wallet = wallet_from_mnemonic(mnemonic_str)
                query = wallet.create_transfer_message(
                    to_raw,
                    int(amount_nano),
                    seqno,
                    payload=None
                )
                boc_b64 = bytes_to_b64str(query["message"].to_boc(False))
                result = await ton_send_boc(cfg, boc_b64)

                tx_hash = None
                if isinstance(result, dict):
                    tx_hash = result.get("hash") or result.get("tx_hash")
                elif isinstance(result, str):
                    tx_hash = result

                set_withdrawal_status(wid, "SENT", tx_hash=tx_hash)

                await bot.send_message(
                    user_id,
                    "✅ Tu premio ha sido enviado a tu wallet.\n"
                    f"ID de retiro: {wid}\n"
                    f"Monto: {amount_nano / 1e9:.6f} TON\n"
                    f"Destino: {to_raw}"
                    + (f"\nTx: {tx_hash}" if tx_hash else "")
                    + "\n\nPor favor espera unos segundos y verifica tu pago en tu wallet TON."
                )

            except Exception as e:
                add_balance_nano(user_id, int(amount_nano))
                set_withdrawal_status(wid, "REFUNDED", error=str(e))
                await bot.send_message(
                    user_id,
                    f"❌ Retiro falló y fue reembolsado.\n"
                    f"ID: {wid}\n"
                    f"Motivo: {e}"
                )

            await asyncio.sleep(1)

        except Exception as e:
            print("withdrawals_worker error:", e)
            await asyncio.sleep(5)


# ----------------------------
# Raffles helpers
# ----------------------------
def create_raffle(
    name: str,
    total_numbers: int,
    ticket_price_nano: int,
    prizes: List[Tuple[int, float]],
    created_by: int
) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        INSERT INTO raffles (name, total_numbers, ticket_price_nano, created_by)
        VALUES (?, ?, ?, ?)
    """, (name, total_numbers, ticket_price_nano, created_by))
    raffle_id = cur.lastrowid

    for num, pct in prizes:
        cur.execute("""
            INSERT INTO raffle_prizes (raffle_id, winning_number, percent)
            VALUES (?, ?, ?)
        """, (raffle_id, num, pct))

    con.commit()
    con.close()
    return int(raffle_id)


def get_open_raffles() -> List[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT id, name, total_numbers, sold_tickets, ticket_price_nano, status
        FROM raffles
        WHERE status='OPEN'
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    con.close()
    return rows


def get_raffle(raffle_id: int) -> Optional[tuple]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT id, name, total_numbers, sold_tickets, ticket_price_nano, status
        FROM raffles
        WHERE id=?
    """, (raffle_id,))
    row = cur.fetchone()
    con.close()
    return row


def assign_tickets(raffle_id: int, user_id: int, count: int) -> Tuple[List[int], int, int]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        SELECT total_numbers, sold_tickets, status
        FROM raffles WHERE id=?
    """, (raffle_id,))
    row = cur.fetchone()
    if not row:
        con.close()
        raise ValueError("Rifa inexistente")

    total_numbers, sold_tickets, status = row
    if status != "OPEN":
        con.close()
        raise ValueError("Rifa no está abierta")

    disponibles = total_numbers - sold_tickets
    if disponibles < count:
        con.close()
        raise ValueError("No hay suficientes boletos disponibles")

    cur.execute("""
        SELECT number FROM raffle_tickets
        WHERE raffle_id=?
        ORDER BY number ASC
    """, (raffle_id,))
    usados = [r[0] for r in cur.fetchall()]
    usados_set = set(usados)

    asignados = []
    num = 1
    while len(asignados) < count and num <= total_numbers:
        if num not in usados_set:
            cur.execute("""
                INSERT INTO raffle_tickets (raffle_id, user_id, number)
                VALUES (?, ?, ?)
            """, (raffle_id, user_id, num))
            asignados.append(num)
        num += 1

    nuevo_sold = sold_tickets + len(asignados)
    new_status = "OPEN"
    if nuevo_sold >= total_numbers:
        new_status = "SOLD_OUT"

    cur.execute("""
        UPDATE raffles
        SET sold_tickets=?, status=?
        WHERE id=?
    """, (nuevo_sold, new_status, raffle_id))

    con.commit()
    con.close()
    return asignados, nuevo_sold, total_numbers


def get_user_tickets_count(raffle_id: int, user_id: int) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        SELECT COUNT(*)
        FROM raffle_tickets
        WHERE raffle_id=? AND user_id=?
    """, (raffle_id, user_id))
    row = cur.fetchone()
    con.close()
    return int(row[0] if row else 0)


async def finalize_raffle(raffle_id: int, bot: Bot) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        SELECT name, total_numbers, ticket_price_nano, status
        FROM raffles WHERE id=?
    """, (raffle_id,))
    row = cur.fetchone()
    if not row:
        con.close()
        return

    name, total_numbers, ticket_price_nano, status = row
    if status == "PAID":
        con.close()
        return

    cur.execute("""
        SELECT winning_number, percent
        FROM raffle_prizes
        WHERE raffle_id=?
    """, (raffle_id,))
    prize_rows = cur.fetchall()

    pot = total_numbers * ticket_price_nano
    winners_info = []

    for winning_number, percent in prize_rows:
        cur.execute("""
            SELECT user_id
            FROM raffle_tickets
            WHERE raffle_id=? AND number=?
        """, (raffle_id, winning_number))
        ticket_row = cur.fetchone()
        if not ticket_row:
            continue
        uid = ticket_row[0]
        amount_nano = int(pot * (percent / 100.0))
        if amount_nano <= 0:
            continue

        add_balance_nano(uid, amount_nano)
        winners_info.append((winning_number, uid, amount_nano))

    cur.execute("""
        SELECT DISTINCT user_id
        FROM raffle_tickets
        WHERE raffle_id=?
    """, (raffle_id,))
    participants = [r[0] for r in cur.fetchall()]

    cur.execute("""
        UPDATE raffles SET status='PAID' WHERE id=?
    """, (raffle_id,))
    con.commit()
    con.close()

    if winners_info:
        lines = [
            "🎉 Rifa finalizada",
            f"Nombre: {name}",
            f"ID de rifa: {raffle_id}",
            "",
            "Ganadores:"
        ]
        for num, uid, amt in winners_info:
            lines.append(f"• Número {num} → user {uid} ganó {amt / 1e9:.4f} TON")
    else:
        lines = [
            "Rifa finalizada.",
            f"Nombre: {name}",
            f"ID de rifa: {raffle_id}",
            "",
            "No hubo ganadores configurados."
        ]
    announce = "\n".join(lines)

    for uid in participants:
        try:
            await bot.send_message(uid, announce)
        except Exception:
            pass


# ----------------------------
# Main / Handlers
# ----------------------------
async def main():
    cfg = load_config()
    init_db()

    bot = Bot(token=cfg.token)
    dp = Dispatcher(storage=MemoryStorage())

    asyncio.create_task(deposits_worker(cfg, bot))
    asyncio.create_task(withdrawals_worker(cfg, bot))

    # ----- /start -----
    @dp.message(Command("start"))
    async def start(m: Message):
        u = m.from_user
        is_new = not participant_exists(u.id)

        referrer_id = parse_referrer_id_from_start(m.text or "", u.id)
        upsert_participant(u.id, u.username, u.first_name, referrer_id)

        address_nb, _ = ensure_user_wallet(u.id)
        my_ref_link = f"https://t.me/{BOT_USERNAME}?start=ref_{u.id}"
        name = u.first_name or (u.username or "usuario")

        if is_new:
            bienvenida = (
                f"Bienvenido(a) {name}.\n\n"
                "🎉 Bienvenido a este Bot de Lotería donde podrás ganar el premio Gordo.\n\n"
                "✅ Tu registro ha sido confirmado.\n"
                f"Tu ID: {u.id}\n\n"
                "📣 Copia y comparte tu enlace de referidor, invita a todos tus amigos:\n"
                f"{my_ref_link}\n\n"
                "💰 Para comprar boletos, deposita TON en tu wallet interna.\n"
                "🏆 Para cobrar premios, registra tu dirección TON de pago con el comando:\n"
                "/set_payout\n"
                "Solo tendrás que registrarla una vez; podrás cambiarla cuando quieras usando de nuevo /set_payout."
            )
        else:
            bienvenida = (
                "Ya estabas registrado.\n\n"
                "👥 Tu enlace de referido:\n"
                f"{my_ref_link}\n\n"
                "Si aún no lo has hecho, registra tu dirección TON para pago de premios con /set_payout."
            )

        CURRENT_MENU[u.id] = "main"

        await m.answer(bienvenida, reply_markup=main_menu())

        await m.answer(
            "➕ Esta es tu dirección de depósito TON para comprar boletos:\n"
            f"<code>{address_nb}</code>",
            parse_mode="HTML"
        )

    # ----- comandos básicos -----
    @dp.message(Command("myid"))
    async def myid(m: Message):
        await m.answer(f"Tu user_id es: {m.from_user.id}")

    @dp.message(Command("mylink"))
    async def mylink(m: Message):
        uid = m.from_user.id
        link = f"https://t.me/{BOT_USERNAME}?start=ref_{uid}"
        await m.answer(f"Tu enlace de referido:\n{link}", reply_markup=main_menu())

    @dp.message(Command("join"))
    async def join(m: Message):
        u = m.from_user
        upsert_participant(u.id, u.username, u.first_name, None)
        ensure_user_wallet(u.id)
        CURRENT_MENU[u.id] = "main"
        await m.answer("✅ Registrado para sorteos.", reply_markup=main_menu())

    @dp.message(Command("leave"))
    async def leave(m: Message):
        ok = remove_participant(m.from_user.id)
        CURRENT_MENU[m.from_user.id] = "main"
        await m.answer("Saliste del sorteo." if ok else "No estabas registrado.", reply_markup=main_menu())

    @dp.message(Command("participants"))
    async def participants(m: Message):
        rows = list_participants()
        await m.answer(f"Participantes registrados: {len(rows)}")

    @dp.message(Command("draw"))
    async def draw(m: Message):
        if not is_admin(m.from_user.id, cfg):
            await m.answer("No autorizado.")
            return
        winner = pick_winner()
        if not winner:
            await m.answer("No hay participantes.")
            return
        user_id, username, first_name = winner
        await m.answer(f"Ganador: {format_user(user_id, username, first_name)}")

    # ----- botones -----
    @dp.message(lambda msg: (msg.text or "") == "👥 Referral")
    async def referral_btn(m: Message):
        uid = m.from_user.id
        link = f"https://t.me/{BOT_USERNAME}?start=ref_{uid}"
        await m.answer(f"👥 Tu enlace de referido:\n{link}", reply_markup=main_menu())

    @dp.message(lambda msg: (msg.text or "") == "➕ Add Balance")
    async def add_balance_btn(m: Message):
        address_nb, _ = ensure_user_wallet(m.from_user.id)
        await m.answer(
            "➕ Depósito TON\n"
            "Copia la dirección para hacer tu depósito.",
            reply_markup=main_menu()
        )
        await m.answer(f"<code>{address_nb}</code>", parse_mode="HTML")

    @dp.message(lambda msg: (msg.text or "") == "💰 My Balance")
    async def my_balance_btn(m: Message):
        row = get_wallet_row(m.from_user.id)
        if not row:
            ensure_user_wallet(m.from_user.id)
            row = get_wallet_row(m.from_user.id)
        balance = (row[4] or 0) / 1e9
        CURRENT_MENU[m.from_user.id] = "main"
        await m.answer(f"💰 Tu saldo interno: {balance:.6f} TON", reply_markup=main_menu())

    @dp.message(lambda msg: (msg.text or "") == "🏆 Withdraw")
    async def withdraw_btn(m: Message):
        row = get_wallet_row(m.from_user.id)

        if not row:
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer(
                "Aún no tienes wallet interna creada.\n\n"
                "Envía /start para crear tu wallet de depósito TON y poder recibir y retirar premios.",
                reply_markup=main_menu()
            )
            return

        balance_nano = int(row[4] or 0)
        payout_raw = row[5]

        if balance_nano <= 0:
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer(
                "🏆 Retiro de premios\n\n"
                "Actualmente no tienes premio acumulado en tu saldo interno.\n"
                "Mejor suerte para la próxima rifa.\n\n"
                "Cuando ganes un premio, aparecerá aquí como saldo disponible para retirar.",
                reply_markup=main_menu()
            )
            return

        if not payout_raw:
            balance_ton = balance_nano / 1e9
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer(
                "🏆 Retiro de premios\n\n"
                f"Tienes un premio acumulado de: {balance_ton:.6f} TON.\n\n"
                "Sin embargo, aún no tienes una dirección TON de pago registrada.\n\n"
                "1) Guarda tu dirección externa TON para premios y retiros:\n"
                "   Envía: /set_payout\n"
                "   y luego pega tu dirección TON cuando el bot te la pida.\n\n"
                "2) Una vez registrada, vuelve a presionar el botón 🏆 Withdraw "
                "para indicar el monto de TON que deseas retirar.",
                reply_markup=main_menu()
            )
            return

        payout_nb = await raw_to_nb_urlsafe(cfg, payout_raw)
        balance_ton = balance_nano / 1e9
        CURRENT_MENU[m.from_user.id] = "main"

        await m.answer(
            "🏆 Retiro de premios\n\n"
            f"Tu saldo de premios disponible es: {balance_ton:.6f} TON.\n\n"
            "Tu dirección de pago registrada es:\n"
            f"{payout_nb}\n\n"
            "Ingresa la cantidad de TON que deseas retirar (solo enteros o un decimal) "
            "usando el comando:\n\n"
            "/withdraw <monto_TON>\n\n"
            "Ejemplos:\n"
            "/withdraw 1\n"
            "/withdraw 1.5\n\n"
            "Después de solicitar el retiro y que el bot confirme el envío, "
            "tu premio será transferido a tu wallet.\n"
            "Espera unos segundos y verifica tu pago en tu wallet TON.",
            reply_markup=main_menu()
        )

    # ----- Buy Ticket: lista rifas activas -----
    @dp.message(lambda msg: (msg.text or "") == "🎫 Buy Ticket")
    async def buy_ticket_menu_btn(m: Message):
        rows = get_open_raffles()
        if not rows:
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer(
                "No hay rifas abiertas en este momento.\n"
                "Cuando haya rifas activas, podrás verlas aquí.",
                reply_markup=main_menu()
            )
            return

        CURRENT_MENU[m.from_user.id] = "raffles"
        await m.answer(
            "🎟️ Loterías activas\n\n"
            "Elige una rifa para ver detalles y comprar boletos:",
            reply_markup=lotteries_keyboard(rows)
        )

    # ----- Botón genérico: ⬅️ Atrás -----
    @dp.message(lambda msg: (msg.text or "") == "⬅️ Atrás")
    async def back_button(m: Message):
        user_id = m.from_user.id
        state = CURRENT_MENU.get(user_id, "main")

        if state == "raffle_detail":
            rows = get_open_raffles()
            if not rows:
                CURRENT_MENU[user_id] = "main"
                await m.answer("No hay rifas abiertas en este momento.", reply_markup=main_menu())
                return
            CURRENT_MENU[user_id] = "raffles"
            await m.answer(
                "🎟️ Loterías activas\n\n"
                "Elige una rifa:",
                reply_markup=lotteries_keyboard(rows)
            )
        elif state == "raffles":
            CURRENT_MENU[user_id] = "main"
            await m.answer("Menú principal:", reply_markup=main_menu())
        else:
            CURRENT_MENU[user_id] = "main"
            await m.answer("Menú principal:", reply_markup=main_menu())

    # ----- Seleccionar una rifa -----
    @dp.message(lambda msg: (msg.text or "").startswith("🎯 "))
    async def select_raffle_btn(m: Message):
        text = m.text or ""
        try:
            idx = text.rfind("(ID ")
            idx2 = text.rfind(")")
            if idx == -1 or idx2 == -1 or idx2 <= idx:
                raise ValueError("Formato de botón inválido")
            id_part = text[idx + 4:idx2].strip()
            raffle_id = int(id_part)
        except Exception:
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer("No pude identificar la rifa seleccionada.", reply_markup=main_menu())
            return

        raffle = get_raffle(raffle_id)
        if not raffle:
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer("Esa rifa ya no existe o no está disponible.", reply_markup=main_menu())
            return

        rid, name, total_numbers, sold_tickets, ticket_price_nano, status = raffle
        if status != "OPEN":
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer("Esa rifa ya no está abierta.", reply_markup=main_menu())
            return

        SELECTED_RAFFLE[m.from_user.id] = rid
        CURRENT_MENU[m.from_user.id] = "raffle_detail"

        price_ton = ticket_price_nano / 1e9
        disponibles = total_numbers - sold_tickets

        await m.answer(
            f"🎯 Has seleccionado la rifa:\n"
            f"Nombre: {name}\n"
            f"ID: {rid}\n"
            f"Boletos vendidos: {sold_tickets}/{total_numbers}\n"
            f"Boletos disponibles: {disponibles}\n"
            f"Precio por boleto: {price_ton:.4f} TON\n\n"
            "Pulsa el botón 🎫 Buy Ticket Now para comprar un boleto.\n"
            "Mientras más boletos tengas, mayor será tu probabilidad de ganar.",
            reply_markup=raffle_detail_menu()
        )

    # ----- Buy Ticket Now -----
    @dp.message(lambda msg: (msg.text or "") == "🎫 Buy Ticket Now")
    async def buy_ticket_selected(m: Message):
        user_id = m.from_user.id

        if user_id not in SELECTED_RAFFLE:
            CURRENT_MENU[user_id] = "main"
            await m.answer(
                "Primero selecciona una rifa en el menú de loterías activas (🎫 Buy Ticket).",
                reply_markup=main_menu()
            )
            return

        raffle_id = SELECTED_RAFFLE[user_id]
        raffle = get_raffle(raffle_id)
        if not raffle:
            CURRENT_MENU[user_id] = "main"
            await m.answer("La rifa seleccionada ya no existe.", reply_markup=main_menu())
            return

        rid, name, total_numbers, sold_tickets, ticket_price_nano, status = raffle
        if status != "OPEN":
            CURRENT_MENU[user_id] = "main"
            await m.answer("La rifa seleccionada ya no está abierta.", reply_markup=main_menu())
            return

        CURRENT_MENU[user_id] = "raffle_detail"

        now = time.time()
        last_ts = LAST_SINGLE_BUY.get(user_id, 0)
        if now - last_ts < 5:
            await m.answer(
                "⏱ Debes esperar 5 segundos entre compras de boletos.",
                reply_markup=raffle_detail_menu()
            )
            return

        row = get_wallet_row(user_id)
        if not row:
            CURRENT_MENU[user_id] = "main"
            await m.answer(
                "Aún no tienes wallet interna creada.\n\n"
                "Envía /start para crear tu wallet de depósito TON y poder comprar boletos.",
                reply_markup=main_menu()
            )
            return

        balance_nano = int(row[4] or 0)
        balance_ton = balance_nano / 1e9
        price_ton = ticket_price_nano / 1e9

        min_play_nano = int(to_nano(5, "ton"))
        if balance_nano < min_play_nano:
            CURRENT_MENU[user_id] = "main"
            await m.answer(
                "Fondos insuficientes, deposita mínimo 5 TON para poder jugar.\n\n"
                "Recarga usando el botón ➕ Add Balance.",
                reply_markup=main_menu()
            )
            return

        if balance_nano < ticket_price_nano:
            await m.answer(
                "Tu saldo actual no alcanza para comprar un boleto.\n"
                f"Precio por boleto: {price_ton:.4f} TON\n"
                f"Tu saldo: {balance_ton:.6f} TON\n\n"
                "Recarga más TON para continuar jugando.",
                reply_markup=raffle_detail_menu()
            )
            return

        add_balance_nano(user_id, -ticket_price_nano)

        try:
            numbers, new_sold, total = assign_tickets(raffle_id, user_id, 1)
        except ValueError as e:
            add_balance_nano(user_id, ticket_price_nano)
            await m.answer(
                f"No se pudo asignar el boleto: {e}",
                reply_markup=raffle_detail_menu()
            )
            return

        LAST_SINGLE_BUY[user_id] = now

        num_str = ", ".join(str(n) for n in numbers)
        new_balance_nano = int(get_wallet_row(user_id)[4] or 0)
        new_balance_ton = new_balance_nano / 1e9

        user_tickets = get_user_tickets_count(raffle_id, user_id)
        prob = (user_tickets / total) * 100.0 if total > 0 else 0.0

        await m.answer(
            f"✅ Boleto comprado en la rifa '{name}' (ID {raffle_id}).\n"
            f"Número asignado: {num_str}\n"
            f"Boletos vendidos: {new_sold}/{total}\n"
            f"Tu saldo restante: {new_balance_ton:.6f} TON\n\n"
            f"Actualmente tienes {user_tickets} boletos de {total}.\n"
            f"Tu probabilidad aproximada de ganar (si se sortea un solo número ganador) es de: {prob:.2f}%.",
            reply_markup=raffle_detail_menu()
        )

        if new_sold >= total:
            CURRENT_MENU[user_id] = "main"
            await m.answer(
                f"🎉 Se han vendido todos los boletos de la rifa '{name}'.\n"
                f"Se ejecutará el reparto de premios.",
                reply_markup=main_menu()
            )
            await finalize_raffle(raffle_id, bot)

    # ----- set_payout -----
    @dp.message(Command("set_payout"))
    async def set_payout_cmd(m: Message, state: FSMContext):
        parts = (m.text or "").split(maxsplit=1)

        if len(parts) < 2:
            await state.set_state(PayoutStates.waiting_address)
            await m.answer(
                "📌 Pega tu dirección TON para premios/retiros en el SIGUIENTE mensaje.\n\n"
                "Ejemplo: UQ... o EQ... o 0:....\n"
                "Tip: pega solo la dirección (sin texto adicional).",
                reply_markup=main_menu()
            )
            return

        addr_in = normalize_ton_address(parts[1])
        if not looks_like_ton_address(addr_in):
            await m.answer(
                "Dirección inválida (formato). Intenta de nuevo con /set_payout y pega solo la dirección.",
                reply_markup=main_menu()
            )
            return

        ensure_user_wallet(m.from_user.id)
        row = get_wallet_row(m.from_user.id)
        prev_raw = row[5] if row else None

        try:
            info = await ton_detect_address(cfg, addr_in)
            is_test = bool(info.get("is_test_only") or info.get("testnet") or False)
            if is_test:
                await m.answer("No se permiten direcciones testnet. Usa mainnet.", reply_markup=main_menu())
                return

            raw = info.get("raw_form") or info.get("raw")
            if not raw:
                await m.answer("No pude convertir a RAW (detectAddress).", reply_markup=main_menu())
                return
        except Exception as e:
            await m.answer(f"Dirección inválida: {e}", reply_markup=main_menu())
            return

        set_payout_address(m.from_user.id, raw)

        if prev_raw and prev_raw != raw:
            msg = "✅ Dirección de pago ACTUALIZADA para retiros/premios."
        elif not prev_raw:
            msg = "✅ Dirección de pago GUARDADA para retiros/premios."
        else:
            msg = "✅ Tu dirección de pago ya estaba registrada (sin cambios)."

        payout_nb = await raw_to_nb_urlsafe(cfg, raw)
        CURRENT_MENU[m.from_user.id] = "main"
        await m.answer(
            f"{msg}\n\n"
            f"NB (url-safe):\n{payout_nb}\n\n"
            f"RAW:\n{raw}",
            reply_markup=main_menu()
        )

    @dp.message(PayoutStates.waiting_address)
    async def set_payout_from_message(m: Message, state: FSMContext):
        addr_in = normalize_ton_address(m.text or "")
        if not looks_like_ton_address(addr_in):
            await m.answer(
                "No parece una dirección TON válida. Pega solo la dirección (UQ..., EQ... o 0:...).",
                reply_markup=main_menu()
            )
            return

        ensure_user_wallet(m.from_user.id)
        row = get_wallet_row(m.from_user.id)
        prev_raw = row[5] if row else None

        try:
            info = await ton_detect_address(cfg, addr_in)
            is_test = bool(info.get("is_test_only") or info.get("testnet") or False)
            if is_test:
                await m.answer("No se permiten direcciones testnet. Usa mainnet.", reply_markup=main_menu())
                return

            raw = info.get("raw_form") or info.get("raw")
            if not raw:
                await m.answer("No pude convertir a RAW (detectAddress).", reply_markup=main_menu())
                return
        except Exception as e:
            await m.answer(f"Dirección inválida: {e}", reply_markup=main_menu())
            return

        set_payout_address(m.from_user.id, raw)
        await state.clear()

        if prev_raw and prev_raw != raw:
            msg = "✅ Dirección de pago ACTUALIZADA para retiros/premios."
        elif not prev_raw:
            msg = "✅ Dirección de pago GUARDADA para retiros/premios."
        else:
            msg = "✅ Tu dirección de pago ya estaba registrada (sin cambios)."

        payout_nb = await raw_to_nb_urlsafe(cfg, raw)
        CURRENT_MENU[m.from_user.id] = "main"
        await m.answer(
            f"{msg}\n\n"
            f"NB (url-safe):\n{payout_nb}\n\n"
            f"RAW:\n{raw}",
            reply_markup=main_menu()
        )

    # ----- withdraw (comando) -----
    @dp.message(Command("withdraw"))
    async def withdraw_cmd(m: Message):
        parts = (m.text or "").split(maxsplit=1)
        if len(parts) < 2:
            await m.answer(
                "Uso: /withdraw <monto_TON>\n"
                "Ejemplos válidos (máximo 1 decimal):\n"
                "/withdraw 1\n"
                "/withdraw 1.5\n\n"
                "Nota: usa punto (.) para decimales.",
                reply_markup=main_menu()
            )
            return

        row = get_wallet_row(m.from_user.id)
        if not row:
            await m.answer("Primero crea tu wallet con /start.", reply_markup=main_menu())
            return

        payout_raw = row[5]
        if not payout_raw:
            await m.answer(
                "No tienes dirección de pago.\n\n"
                "Envía: /set_payout\n"
                "y luego pega tu dirección TON cuando el bot te la pida.",
                reply_markup=main_menu()
            )
            return

        amount_str = (parts[1] or "").strip()

        if "," in amount_str:
            await m.answer(
                "Formato inválido.\n"
                "Usa punto (.) para decimales.\n\n"
                "Ejemplos:\n"
                "/withdraw 1\n"
                "/withdraw 1.5",
                reply_markup=main_menu()
            )
            return

        if not DECIMAL_1_RE.match(amount_str):
            await m.answer(
                "Monto inválido. Solo se permiten enteros o con un decimal.\n\n"
                "Ejemplos válidos:\n"
                "/withdraw 1\n"
                "/withdraw 1.5\n",
                reply_markup=main_menu()
            )
            return

        try:
            amount_ton = float(amount_str)
            if amount_ton <= 0:
                raise ValueError()
        except Exception:
            await m.answer(
                "Monto inválido.\n"
                "Ejemplos:\n"
                "/withdraw 1\n"
                "/withdraw 1.5",
                reply_markup=main_menu()
            )
            return

        amount_nano = int(to_nano(amount_ton, "ton"))
        balance_nano = int(row[4] or 0)

        fee_buffer = int(to_nano(0.02, "ton"))
        if amount_nano + fee_buffer > balance_nano:
            await m.answer("Saldo insuficiente (considerando fees).", reply_markup=main_menu())
            return

        add_balance_nano(m.from_user.id, -amount_nano)

        wid = create_withdrawal(m.from_user.id, payout_raw, amount_nano)
        await m.answer(
            f"✅ Retiro en cola (ID {wid}).\n"
            f"Monto: {amount_ton:.1f} TON\n"
            f"Destino (RAW): {payout_raw}\n"
            "Estado: QUEUED → envío automático.",
            reply_markup=main_menu()
        )

    # ----- mypayout -----
    @dp.message(Command("mypayout"))
    async def mypayout_cmd(m: Message):
        row = get_wallet_row(m.from_user.id)
        if not row:
            await m.answer("No existe tu wallet. Usa /start primero.", reply_markup=main_menu())
            return

        payout_raw = row[5]
        if not payout_raw:
            await m.answer(
                "Aún no tienes dirección de pago.\n\n"
                "Envía: /set_payout\n"
                "y luego pega tu dirección TON cuando el bot te la pida.",
                reply_markup=main_menu()
            )
            return

        payout_nb = await raw_to_nb_urlsafe(cfg, payout_raw)
        await m.answer(
            "✅ Dirección de pago registrada:\n\n"
            f"NB (url-safe):\n{payout_nb}\n\n"
            f"RAW:\n{payout_raw}",
            reply_markup=main_menu()
        )

    # ----- admin check payout -----
    @dp.message(Command("checkpayout"))
    async def checkpayout_cmd(m: Message):
        if not is_admin(m.from_user.id, cfg):
            await m.answer("No autorizado.")
            return

        parts = (m.text or "").split()
        if len(parts) < 2 or not parts[1].isdigit():
            await m.answer("Uso: /checkpayout <user_id>")
            return

        uid = int(parts[1])
        row = get_wallet_row(uid)
        if not row:
            await m.answer("Ese user_id no tiene wallet.")
            return

        payout_raw = row[5]
        if not payout_raw:
            await m.answer(f"user_id: {uid}\nNo tiene payout registrado.")
            return

        payout_nb = await raw_to_nb_urlsafe(cfg, payout_raw)
        await m.answer(
            f"user_id: {uid}\n\n"
            f"NB (url-safe):\n{payout_nb}\n\n"
            f"RAW:\n{payout_raw}"
        )

    # ----- admin cola de retiros -----
    @dp.message(Command("withdraws"))
    async def withdraws_cmd(m: Message):
        if not is_admin(m.from_user.id, cfg):
            await m.answer("No autorizado.")
            return
        rows = list_withdrawals("QUEUED", 20)
        if not rows:
            await m.answer("No hay retiros en cola.")
            return
        lines = []
        for wid, uid, to, amt, st, ca, ua in rows:
            lines.append(f"ID {wid} | user {uid} | {amt / 1e9:.6f} TON | {st}")
        await m.answer("\n".join(lines))

    # ----- admin stats -----
    @dp.message(Command("admin_stats"))
    async def admin_stats_cmd(m: Message):
        if not is_admin(m.from_user.id, cfg):
            await m.answer("No autorizado.")
            return

        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()

        cur.execute("SELECT COUNT(*) FROM participants")
        row = cur.fetchone()
        total_players = int(row[0] or 0)

        cur.execute("SELECT COUNT(*) FROM raffle_tickets")
        row = cur.fetchone()
        total_tickets = int(row[0] or 0)

        cur.execute("SELECT COUNT(DISTINCT user_id) FROM raffle_tickets")
        row = cur.fetchone()
        players_with_tickets = int(row[0] or 0)

        cur.execute("SELECT COUNT(*) FROM raffles")
        row = cur.fetchone()
        total_raffles = int(row[0] or 0)

        cur.execute("SELECT COUNT(*) FROM raffles WHERE status='OPEN'")
        row = cur.fetchone()
        open_raffles = int(row[0] or 0)

        con.close()

        closed_raffles = total_raffles - open_raffles

        await m.answer(
            "📊 Estadísticas del sistema\n\n"
            f"👤 Jugadores registrados: {total_players}\n"
            f"🎟️ Boletos comprados (total): {total_tickets}\n"
            f"👥 Jugadores que han comprado al menos 1 boleto: {players_with_tickets}\n\n"
            f"🎰 Rifas totales: {total_raffles}\n"
            f"   - Abiertas: {open_raffles}\n"
            f"   - Cerradas: {closed_raffles}"
        )

    # ----- admin broadcast -----
    @dp.message(Command("broadcast"))
    async def broadcast_cmd(m: Message):
        if not is_admin(m.from_user.id, cfg):
            await m.answer("No autorizado.")
            return

        parts = (m.text or "").split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            await m.answer(
                "Uso: /broadcast <mensaje>\n\n"
                "Ejemplo:\n"
                "/broadcast Mañana abrimos una nueva Rifa Navideña, no te la pierdas."
            )
            return

        text = parts[1].strip()

        rows = list_participants()
        if not rows:
            await m.answer("No hay jugadores registrados para enviar el mensaje.")
            return

        ok_count = 0
        fail_count = 0

        for user_id, username, first_name in rows:
            try:
                await bot.send_message(
                    user_id,
                    "📣 Mensaje del administrador:\n\n" + text
                )
                ok_count += 1
            except Exception:
                fail_count += 1
            await asyncio.sleep(0.05)

        await m.answer(
            "📤 Broadcast finalizado.\n"
            f"Enviados correctamente: {ok_count}\n"
            f"Fallidos (bot bloqueado o error): {fail_count}"
        )

    # ----- admin new_raffle -----
    @dp.message(Command("new_raffle"))
    async def new_raffle_cmd(m: Message):
        if not is_admin(m.from_user.id, cfg):
            await m.answer("No autorizado.")
            return

        parts = (m.text or "").split(maxsplit=1)
        if len(parts) < 2:
            await m.answer(
                "Uso:\n"
                "/new_raffle NombreRifa|total_numeros|precio_boleto_TON|num1:pct1,num2:pct2,...\n"
                "Ejemplo:\n"
                "/new_raffle Rifa_Navideña|10|1|1:60,2:20,3:10"
            )
            return

        try:
            payload = parts[1]
            name, total_s, price_s, prizes_s = [x.strip() for x in payload.split("|")]
            total_numbers = int(total_s)
            price_ton = float(price_s)
            ticket_price_nano = int(to_nano(price_ton, "ton"))

            prizes: List[Tuple[int, float]] = []
            for chunk in prizes_s.split(","):
                num_s, pct_s = chunk.split(":")
                num = int(num_s.strip())
                pct = float(pct_s.strip())
                prizes.append((num, pct))

            sum_pct = sum(p for _, p in prizes)
            if sum_pct > 100.0 + 1e-6:
                await m.answer("La suma de porcentajes no puede ser mayor a 100%.")
                return

            raffle_id = create_raffle(name, total_numbers, ticket_price_nano, prizes, m.from_user.id)
            await m.answer(
                f"✅ Rifa creada.\n"
                f"ID: {raffle_id}\n"
                f"Nombre: {name}\n"
                f"Números: {total_numbers}\n"
                f"Precio boleto: {price_ton:.4f} TON\n"
                f"Premios: {prizes_s}"
            )
        except Exception as e:
            await m.answer(f"Error al crear rifa: {e}")

    # ----- rifas abiertas (comando) -----
    @dp.message(Command("raffles"))
    async def raffles_cmd(m: Message):
        rows = get_open_raffles()
        if not rows:
            CURRENT_MENU[m.from_user.id] = "main"
            await m.answer("No hay rifas abiertas en este momento.", reply_markup=main_menu())
            return

        lines = ["🎟️ Rifas abiertas:\n"]
        for rid, name, total, sold, price_nano, status in rows:
            price_ton = price_nano / 1e9
            lines.append(
                f"ID {rid} | {name}\n"
                f"Boletos vendidos: {sold}/{total}\n"
                f"Precio por boleto: {price_ton:.4f} TON\n"
            )
        lines.append(
            "\nPara jugar, usa el botón 🎫 Buy Ticket en el menú principal,\n"
            "elige una rifa y luego pulsa 🎫 Buy Ticket Now para comprar un boleto."
        )

        CURRENT_MENU[m.from_user.id] = "main"
        await m.answer("\n".join(lines), reply_markup=main_menu())

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

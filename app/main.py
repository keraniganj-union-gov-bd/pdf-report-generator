from pathlib import Path
import base64, html, io, json, os, re, sqlite3, tempfile, uuid
from datetime import datetime

import fitz
import qrcode
from PIL import Image
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
import subprocess, time, shutil, platform, secrets, hashlib, hmac, time as _time
from typing import Optional
from urllib.parse import urlencode, urlsplit, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from fastapi import Cookie, Depends
# WeasyPrint is optional. Render/production environments may not have it.
# Never let a missing optional PDF engine prevent the FastAPI app from starting.
try:
    from weasyprint import HTML as WeasyHTML
except ImportError:
    WeasyHTML = None
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, text
BASE = Path(__file__).resolve().parent.parent

DATA = BASE / "data"
GENERATED = BASE / "generated"
STATIC = BASE / "static"
FONT = BASE / "fonts" / "NotoSansBengali-Regular.ttf"
FONT_REGULAR = BASE / "fonts" / "NotoSansBengali-Regular.ttf"
FONT_SEMIBOLD = BASE / "fonts" / "NotoSansBengali-SemiBold.ttf"
DB = DATA / "dev.sqlite3"
DATA.mkdir(exist_ok=True); GENERATED.mkdir(exist_ok=True)
BACKGROUNDS = DATA / "backgrounds"
BACKGROUNDS.mkdir(exist_ok=True)

app = FastAPI(title="Free PDF Report Generator V46")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

FIELDS = [
    "national_id","pin","voter_no","voter_area","voter_at",
    "name_bn","name_en","dob","spouse","father","mother",
    "gender","occupation","blood_group","birth_place",
    "present_address","permanent_address","photo_b64","qr_b64"
]

LABELS = {
    "national_id":"জাতীয় পরিচয়পত্র নম্বর",
    "pin":"পিন",
    "voter_no":"ভোটার নম্বর",
    "voter_area":"ভোটার এলাকা",
    "voter_at":"ভোটার অবস্থান",
    "name_bn":"নাম (বাংলা)",
    "name_en":"নাম (ইংরেজি)",
    "dob":"জন্ম তারিখ",
    "spouse":"স্বামী/স্ত্রীর নাম",
    "father":"পিতার নাম",
    "mother":"মাতার নাম",
    "gender":"লিঙ্গ",
    "occupation":"পেশা",
    "blood_group":"রক্তের গ্রুপ",
    "birth_place":"জন্মস্থান",
    "present_address":"বর্তমান ঠিকানা",
    "permanent_address":"স্থায়ী ঠিকানা",
}


# ---------------------------------------------------------------------------
# Production web database/auth layer.
# Uses CockroachDB/PostgreSQL when DATABASE_URL is set; SQLite otherwise.
# The existing V59 SQLite development layer is retained for compatibility.
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if DATABASE_URL:
    PROD_DB_URL = DATABASE_URL

    if PROD_DB_URL.startswith("postgres://"):
        PROD_DB_URL = "postgresql+psycopg2://" + PROD_DB_URL[len("postgres://"):]
    elif PROD_DB_URL.startswith("postgresql://"):
        PROD_DB_URL = "postgresql+psycopg2://" + PROD_DB_URL[len("postgresql://"):]
    elif PROD_DB_URL.startswith("cockroachdb://"):
        PROD_DB_URL = "cockroachdb+psycopg2://" + PROD_DB_URL[len("cockroachdb://"):]

else:
    PROD_DB_URL = f"sqlite:///{(DATA / 'web.sqlite3').as_posix()}"


prod_engine = create_engine(
    PROD_DB_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if PROD_DB_URL.startswith("sqlite") else {},
)

SESSION_SECRET = os.getenv("SESSION_SECRET", "CHANGE_THIS_SESSION_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeThisAdminPassword123!")

# ---------------------------------------------------------------------------
# DB Clouds voter-search integration. Keep the API key server-side only.
# Set these in Render/production Environment Variables:
#   DBCLOUDS_API_URL       = the real search API endpoint (NOT test-api.html)
#   DBCLOUDS_API_KEY       = the API key supplied by DB Clouds
#   DBCLOUDS_API_METHOD    = POST (default) or GET
#   DBCLOUDS_API_KEY_HEADER= X-API-Key (default) or Authorization
# ---------------------------------------------------------------------------
DBCLOUDS_API_URL = os.getenv("DBCLOUDS_API_URL", "").strip()
DBCLOUDS_API_KEY = os.getenv("DBCLOUDS_API_KEY", "").strip()
DBCLOUDS_API_METHOD = os.getenv("DBCLOUDS_API_METHOD", "POST").strip().upper() or "POST"
DBCLOUDS_API_KEY_HEADER = os.getenv("DBCLOUDS_API_KEY_HEADER", "X-API-Key").strip() or "X-API-Key"
DBCLOUDS_API_TIMEOUT = int(os.getenv("DBCLOUDS_API_TIMEOUT", "25") or 25)

def _hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000).hex()
    return f"{salt}${digest}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000).hex()
        return hmac.compare_digest(check, digest)
    except Exception:
        return False

def _token(user_id: int, role: str) -> str:
    payload = f"{user_id}:{role}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def _read_token(token: str):
    try:
        user_id, role, sig = token.split(":", 2)
        payload = f"{user_id}:{role}"
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return int(user_id), role
    except Exception:
        return None

def prod_init():
    with prod_engine.begin() as c:
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'customer',
    active INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(40) NOT NULL,
    full_name VARCHAR(255) DEFAULT '',
    mobile VARCHAR(50) DEFAULT ''
)
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_wallets (
                user_id INTEGER PRIMARY KEY,
                credits INTEGER NOT NULL DEFAULT 0
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_generations (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                nid VARCHAR(50),
                filename VARCHAR(255),
                channel VARCHAR(20) NOT NULL DEFAULT 'web',
                charged INTEGER NOT NULL DEFAULT 0,
                pdf_data TEXT,
                person_name TEXT DEFAULT '',
                dob VARCHAR(50) DEFAULT '',
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_settings (
                key VARCHAR(100) PRIMARY KEY,
                value TEXT NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_backgrounds (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                mime VARCHAR(100) NOT NULL,
                data TEXT NOT NULL,
                selected INTEGER NOT NULL DEFAULT 0,
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_birth_backgrounds (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                mime VARCHAR(100) NOT NULL,
                data TEXT NOT NULL,
                selected INTEGER NOT NULL DEFAULT 0,
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS web_payments (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                credits INTEGER NOT NULL,
                transaction_id VARCHAR(100) UNIQUE NOT NULL,
                sender_bkash VARCHAR(50) DEFAULT '',
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                note TEXT DEFAULT '',
                created_at VARCHAR(40) NOT NULL,
                verified_at VARCHAR(40)
            )
        """))
        # Backward-compatible migrations. Each ALTER runs in its own
        # savepoint so a harmless "column already exists" error cannot abort
        # the main PostgreSQL/Neon transaction.
        migrations = [
            "ALTER TABLE web_payments ADD COLUMN sender_bkash VARCHAR(50)",
            "ALTER TABLE web_payments ADD COLUMN note TEXT",
            "ALTER TABLE web_payments ADD COLUMN verified_at VARCHAR(40)",
            "ALTER TABLE web_generations ADD COLUMN pdf_data TEXT",
            "ALTER TABLE web_generations ADD COLUMN person_name TEXT DEFAULT ''",
            "ALTER TABLE web_generations ADD COLUMN dob VARCHAR(50) DEFAULT ''",
        ]
        for ddl in migrations:
            try:
                with c.begin_nested():
                    c.execute(text(ddl))
            except Exception:
                pass

        c.execute(text("""
            CREATE TABLE IF NOT EXISTS api_plans (
                id INTEGER PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                price VARCHAR(50) NOT NULL DEFAULT '0',
                monthly_limit INTEGER NOT NULL DEFAULT 1000,
                rate_limit INTEGER NOT NULL DEFAULT 30,
                max_file_mb INTEGER NOT NULL DEFAULT 15,
                active INTEGER NOT NULL DEFAULT 1,
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS api_clients (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) DEFAULT '',
                website VARCHAR(500) DEFAULT '',
                plan_id INTEGER NOT NULL,
                api_key_hash VARCHAR(128) NOT NULL UNIQUE,
                api_key_prefix VARCHAR(30) NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                expires_at VARCHAR(40) DEFAULT '',
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS api_requests (
                id INTEGER PRIMARY KEY,
                client_id INTEGER NOT NULL,
                request_id VARCHAR(80) UNIQUE NOT NULL,
                status VARCHAR(20) NOT NULL,
                filename VARCHAR(255) DEFAULT '',
                nid VARCHAR(80) DEFAULT '',
                person_name TEXT DEFAULT '',
                dob VARCHAR(50) DEFAULT '',
                processing_ms INTEGER DEFAULT 0,
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS voter_searches (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                query_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                unlocked INTEGER NOT NULL DEFAULT 0,
                charged INTEGER NOT NULL DEFAULT 0,
                created_at VARCHAR(40) NOT NULL
            )
        """))
        c.execute(text("INSERT INTO api_plans(id,name,price,monthly_limit,rate_limit,max_file_mb,active,created_at) VALUES(1,'Basic','0',1000,30,15,1,:t) ON CONFLICT(id) DO NOTHING"), {"t": datetime.utcnow().isoformat()})

        # Seed IDs manually so SQLite and Cockroach both work without
        # database-specific autoincrement syntax.
        admin = c.execute(text("SELECT id FROM web_users WHERE email=:e"), {"e": ADMIN_EMAIL}).fetchone()
        if not admin:
            c.execute(text(
                "INSERT INTO web_users(id,email,password_hash,role,active,created_at) "
                "VALUES(:id,:e,:p,'admin',1,:t)"
            ), {"id": 1, "e": ADMIN_EMAIL, "p": _hash_password(ADMIN_PASSWORD), "t": datetime.utcnow().isoformat()})
            c.execute(text("INSERT INTO web_wallets(user_id,credits) VALUES(1,0)"))
        for key, value in [("web_price","1"),("voter_search_price","1"),("api_price","1"),("sign_to_server_price","1"),("auto_birth_price","1"),("bkash_number","01925211591"),("whatsapp_group_link","")]:
            c.execute(text(
                "INSERT INTO web_settings(key,value) VALUES(:k,:v) "
                "ON CONFLICT(key) DO NOTHING"
            ), {"k": key, "v": value})
        # Keep the new Sign to Server price backward-compatible with the
        # previous web_price setting on existing installations.
        existing_sign = c.execute(text("SELECT value FROM web_settings WHERE key=:k"), {"k":"sign_to_server_price"}).fetchone()
        if existing_sign is None:
            old_web = c.execute(text("SELECT value FROM web_settings WHERE key=:k"), {"k":"web_price"}).fetchone()
            c.execute(text("INSERT INTO web_settings(key,value) VALUES(:k,:v) ON CONFLICT(key) DO NOTHING"), {"k":"sign_to_server_price", "v": str(old_web[0]) if old_web else "1"})

prod_init()

def prod_setting(key: str, default: str = "") -> str:
    with prod_engine.begin() as c:
        r = c.execute(text("SELECT value FROM web_settings WHERE key=:k"), {"k": key}).fetchone()
        return str(r[0]) if r else default

def prod_set_setting(key: str, value: str):
    with prod_engine.begin() as c:
        c.execute(text(
            "INSERT INTO web_settings(key,value) VALUES(:k,:v) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        ), {"k": key, "v": str(value)})

def current_user(session: str | None):
    if not session:
        raise HTTPException(401, "Login required")
    parsed = _read_token(session)
    if not parsed:
        raise HTTPException(401, "Invalid session")
    uid, role = parsed
    with prod_engine.begin() as c:
        r = c.execute(text(
            "SELECT id,email,role,active FROM web_users WHERE id=:id"
        ), {"id": uid}).mappings().first()
    if not r or not r["active"] or r["role"] != role:
        raise HTTPException(401, "Invalid session")
    return dict(r)

def require_admin(session: str | None):
    u = current_user(session)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return u

def require_customer(session: str | None):
    u = current_user(session)
    if u["role"] not in ("customer","admin"):
        raise HTTPException(403, "Customer access required")
    return u

def _next_id(c, table: str) -> int:
    r = c.execute(text(f"SELECT COALESCE(MAX(id),0)+1 FROM {table}")).fetchone()
    return int(r[0])

def prod_balance(user_id: int) -> int:
    with prod_engine.begin() as c:
        r = c.execute(text("SELECT credits FROM web_wallets WHERE user_id=:u"), {"u": user_id}).fetchone()
        return int(r[0]) if r else 0

def prod_charge(user_id: int, amount: int):
    with prod_engine.begin() as c:
        r = c.execute(text("SELECT credits FROM web_wallets WHERE user_id=:u"), {"u": user_id}).fetchone()
        bal = int(r[0]) if r else 0
        if bal < amount:
            raise HTTPException(402, "Insufficient balance")
        new = bal - amount
        c.execute(text("UPDATE web_wallets SET credits=:b WHERE user_id=:u"), {"b": new, "u": user_id})
        return new

def save_generation(user_id: int, nid: str, filename: str, charged: int, person_name: str = "", dob: str = "", channel: str = "web"):
    """Save generation metadata for the customer/admin audit history."""
    now = datetime.utcnow().isoformat()
    with prod_engine.begin() as c:
        gid = _next_id(c, "web_generations")
        c.execute(text(
            "INSERT INTO web_generations(id,user_id,nid,filename,channel,charged,pdf_data,person_name,dob,created_at) "
            "VALUES(:id,:u,:n,:f,:channel,:ch,'',:person_name,:dob,:t)"
        ), {
            "id": gid, "u": user_id, "n": nid, "f": filename,
            "channel": channel, "ch": charged, "person_name": person_name,
            "dob": dob, "t": now
        })


def set_default_background_db(name: str, mime: str, data_b64: str):
    with prod_engine.begin() as c:
        c.execute(text("UPDATE web_backgrounds SET selected=0"))
        bid = _next_id(c, "web_backgrounds")
        c.execute(text(
            "INSERT INTO web_backgrounds(id,name,mime,data,selected,created_at) "
            "VALUES(:id,:n,:m,:d,1,:t)"
        ), {"id":bid,"n":name,"m":mime,"d":data_b64,"t":datetime.utcnow().isoformat()})

def get_default_background_db():
    with prod_engine.begin() as c:
        r = c.execute(text(
            "SELECT name,mime,data FROM web_backgrounds WHERE selected=1 ORDER BY id DESC"
        )).mappings().first()
    return dict(r) if r else None

def set_birth_background_db(name: str, mime: str, data_b64: str):
    with prod_engine.begin() as c:
        c.execute(text("UPDATE web_birth_backgrounds SET selected=0"))
        bid = _next_id(c, "web_birth_backgrounds")
        c.execute(text(
            "INSERT INTO web_birth_backgrounds(id,name,mime,data,selected,created_at) "
            "VALUES(:id,:n,:m,:d,1,:t)"
        ), {"id":bid,"n":name,"m":mime,"d":data_b64,"t":datetime.utcnow().isoformat()})


def get_birth_background_db():
    with prod_engine.begin() as c:
        r = c.execute(text(
            "SELECT name,mime,data FROM web_birth_backgrounds "
            "WHERE selected=1 ORDER BY id DESC"
        )).mappings().first()
    return dict(r) if r else None


def sync_default_background_to_local():
    bg = get_default_background_db()
    if not bg:
        return
    try:
        import base64 as _b64
        BACKGROUNDS.mkdir(exist_ok=True)
        path = BACKGROUNDS / Path(bg["name"]).name
        path.write_bytes(_b64.b64decode(bg["data"]))
        set_setting_str("background_image", path.name)
    except Exception:
        pass

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS wallets(owner TEXT PRIMARY KEY,credits INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS api_keys(api_key TEXT PRIMARY KEY,owner TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT,owner TEXT,channel TEXT,amount INTEGER,balance_after INTEGER,created_at TEXT);
    """)
    c.execute("INSERT OR IGNORE INTO settings VALUES('web_price','1')")
    c.execute("INSERT OR IGNORE INTO settings VALUES('api_price','1')")
    c.execute("INSERT OR IGNORE INTO wallets VALUES('demo',100)")
    c.execute("INSERT OR IGNORE INTO api_keys VALUES('dev_test_key_change_me','demo',1)")
    c.commit(); c.close()
init_db()

def setting(k):
    c=db(); r=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone(); c.close()
    return int(r["value"]) if r else 1

def set_setting(k,v):
    c=db(); c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,str(int(v))))
    c.commit(); c.close()

def setting_str(k, default=""):
    c=db(); r=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone(); c.close()
    return str(r["value"]) if r else default

def set_setting_str(k,v):
    c=db(); c.execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (k, str(v))
    )
    c.commit(); c.close()

def balance(owner="demo"):
    c=db(); r=c.execute("SELECT credits FROM wallets WHERE owner=?",(owner,)).fetchone(); c.close()
    return int(r["credits"])

def charge(owner, amount, channel):
    c=db(); r=c.execute("SELECT credits FROM wallets WHERE owner=?",(owner,)).fetchone()
    if not r or r["credits"] < amount:
        c.close(); raise HTTPException(402,"Insufficient credits")
    new=r["credits"]-amount
    c.execute("UPDATE wallets SET credits=? WHERE owner=?",(new,owner))
    c.execute("INSERT INTO ledger(owner,channel,amount,balance_after,created_at) VALUES(?,?,?,?,?)",
              (owner,channel,amount,new,datetime.utcnow().isoformat()))
    c.commit(); c.close(); return new

def first(text, patterns):
    for p in patterns:
        m=re.search(p,text,re.I|re.M)
        if m: return m.group(1).strip()
    return ""

def block(text, heading, stops):
    m=re.search(heading,text,re.I|re.M)
    if not m: return ""
    rest=text[m.end():]
    stop="|".join(stops)
    n=re.search(stop,rest,re.I|re.M)
    s=rest[:n.start()] if n else rest[:1000]
    return " ".join(x.strip() for x in s.splitlines() if x.strip())

def normalize_bn_address(s):
    """Parse the source address by field labels, then render in the requested order.
    Output starts with Holding No, omits RMO, ends with Division, and uses commas.
    """
    if not s:
        return ""

    # Normalize source text so labels can be found even when line wrapping differs.
    s = re.sub(r"\s+", " ", s).strip()

    specs = [
        ("holding", [r"Home/Holding No"]),
        ("post_office", [r"Post Office"]),
        ("postal_code", [r"Postal Code"]),
        ("village", [r"Village/Road"]),
        ("additional_village", [r"Additional Village/Road"]),
        ("ward_union", [r"Ward For Union Porishod", r"Ward For Union Parishod", r"Ward For Union Parishad"]),
        ("union_ward", [r"Union/Ward"]),
        ("mouza", [r"Mouza/Moholla"]),
        ("additional_mouza", [r"Additional Mouza/Moholla"]),
        ("upazila", [r"Upazila"]),
        ("city", [r"\(1\)\s*City Corporation Or Municipality", r"City Corporation Or Municipality"]),
        ("rmo_skip", [r"RMO"]),
        ("district", [r"District"]),
        ("region", [r"Region"]),
        ("division", [r"Division"]),
    ]

    # Find all labels and their positions; choose earliest match for each field.
    found = []
    for key, patterns in specs:
        pos = None
        label_len = 0
        for pat in patterns:
            m = re.search(pat, s, re.I)
            if m and (pos is None or m.start() < pos):
                pos = m.start()
                label_len = m.end() - m.start()
        if pos is not None:
            found.append((pos, key, label_len))

    found.sort()
    values = {}
    for idx, (pos, key, label_len) in enumerate(found):
        next_pos = found[idx+1][0] if idx + 1 < len(found) else len(s)
        val = s[pos + label_len:next_pos].strip(" ,:-")
        values[key] = val

    bn = {
        "holding":"হোল্ডিং নং",
        "village":"গ্রাম/রাস্তা",
        "additional_village":"অতিরিক্ত গ্রাম/রাস্তা",
        "ward_union":"ইউনিয়ন পরিষদের ওয়ার্ড",
        "union_ward":"ইউনিয়ন/ওয়ার্ড",
        "mouza":"মৌজা/মহল্লা",
        "additional_mouza":"অতিরিক্ত মৌজা/মহল্লা",
        "upazila":"উপজেলা",
        "city":"সিটি কর্পোরেশন/পৌরসভা",
        "post_office":"ডাকঘর",
        "postal_code":"পোস্টাল কোড",
        "district":"জেলা",
        "region":"অঞ্চল",
        "division":"বিভাগ",
    }

    # Required order: start at Holding No, end at Division. RMO is intentionally omitted.
    order = [
        "holding", "village", "additional_village",
        "ward_union", "union_ward", "mouza", "additional_mouza",
        "upazila", "city", "post_office", "postal_code",
        "district", "region", "division"
    ]

    parts = []
    for key in order:
        value = values.get(key, "").strip()
        if not value:
            continue
        # Keep source values, but remove accidental trailing punctuation.
        value = re.sub(r"\s*,\s*$", "", value)
        parts.append(f"{bn[key]}- {value}")

    result = ", ".join(parts) + ("।" if parts else "")
    # Last-resort protection against any English structural text leaking into
    # the final address paragraph.
    result = re.sub(
        r"\b(?:Additional|Village|Road|Ward|For|Union|Parishod|Porishod|Parishad|Porishad|Mouza|"
        r"Moholla|Mohalla|Upazila|City|Corporation|Municipality|Post|Office|"
        r"Postal|Code|District|Region|Division|Holding|Home|RMO)\b",
        "",
        result, flags=re.I
    )
    result = re.sub(r"\s{2,}", " ", result)
    result = re.sub(r"\s*,\s*", ", ", result)
    return result


def _line_clean(s):
    s = (s or "").replace("\u00a0", " ")
    s = re.sub(r"\s+", " ", s)
    return s.strip(" ,:-")

def _norm_address_text(s):
    s = (s or "").replace("\u00a0", " ")
    s = re.sub(r"\s+", " ", s)
    # Normalize spacing around slash so labels match consistently.
    s = re.sub(r"\s*/\s*", "/", s)
    return s.strip()


def _bangla_digits(value):
    trans = str.maketrans("0123456789", "০১২৩৪৫৬৭৮৯")
    return str(value).translate(trans)

def _address_bangla_only(value):
    """
    Strictly sanitize address values. Structural English phrases that leaked
    from OCR/source labels are converted to Bengali or removed. This is
    applied only to address values, not to the English Name field.
    """
    v = _line_clean(value)

    # Convert compound source-label phrases BEFORE removing individual words.
    phrase_replacements = [
        (r"\bWard\s+For\s+Union\s+Parishod\b", "ওয়ার্ড"),
        (r"\bWard\s+For\s+Union\s+Parishad\b", "ওয়ার্ড"),
        (r"\bAdditional\s+Village\s*/\s*Road\b", "অতিরিক্ত গ্রাম/রাস্তা"),
        (r"\bVillage\s*/\s*Road\b", "গ্রাম/রাস্তা"),
        (r"\bAdditional\s+Mouza\s*/\s*Moholla\b", "অতিরিক্ত মৌজা/মহল্লা"),
        (r"\bAdditional\s+Mouza\s*/\s*Mohalla\b", "অতিরিক্ত মৌজা/মহল্লা"),
        (r"\bMouza\s*/\s*Moholla\b", "মৌজা/মহল্লা"),
        (r"\bMouza\s*/\s*Mohalla\b", "মৌজা/মহল্লা"),
        (r"\bUnion\s*/\s*Ward\b", "ইউনিয়ন/ওয়ার্ড"),
        (r"\bCity\s+Corporation\s+Or\s+Municipality\b", "সিটি কর্পোরেশন/পৌরসভা"),
        (r"\bPost\s+Office\b", "পোস্ট অফিস"),
        (r"\bPostal\s+Code\b", "পোস্ট কোড"),
    ]
    for pat, rep in phrase_replacements:
        v = re.sub(pat, rep, v, flags=re.I)

    # Common English structural words which can still leak.
    word_replacements = [
        (r"\bAdditional\b", "অতিরিক্ত"),
        (r"\bVillage\b", "গ্রাম"),
        (r"\bRoad\b", "রাস্তা"),
        (r"\bWard\b", "ওয়ার্ড"),
        (r"\bUnion\b", "ইউনিয়ন"),
        (r"\bParishod\b", "পরিষদ"),
        (r"\bParishad\b", "পরিষদ"),
        (r"\bMouza\b", "মৌজা"),
        (r"\bMoholla\b", "মহল্লা"),
        (r"\bMohalla\b", "মহল্লা"),
        (r"\b(?:Upazila|Upozila|Upozilla|Upazilla)\b", "উপজেলা"),
        (r"\bCity\b", "সিটি"),
        (r"\bCorporation\b", "কর্পোরেশন"),
        (r"\bMunicipality\b", "পৌরসভা"),
        (r"\bPost\b", "ডাক"),
        (r"\bOffice\b", "অফিস"),
        (r"\bPostal\b", "পোস্টাল"),
        (r"\bCode\b", "কোড"),
        (r"\bDistrict\b", "জেলা"),
        (r"\bRegion\b", "অঞ্চল"),
        (r"\bDivision\b", "বিভাগ"),
        (r"\bHolding\b", "হোল্ডিং"),
        (r"\bHome\b", "বাসা"),
        (r"\bRMO\b", ""),
    ]
    for pat, rep in word_replacements:
        v = re.sub(pat, rep, v, flags=re.I)

    # Specific place names observed in the supplied source.
    place_map = {
        "dhaka": "ঢাকা",
        "keraniganj": "কেরানীগঞ্জ",
        "konda": "কোন্ডা",
        "janjira": "জাঞ্জিরা",
        "mohammadpur": "মোহাম্মদপুর",
        "mirpur": "মিরপুর",
        "savar": "সাভার",
        "demra": "ডেমরা",
        "dohar": "দোহার",
        "nawabganj": "নবাবগঞ্জ",
    }
    for eng, bn in sorted(place_map.items(), key=lambda x: -len(x[0])):
        v = re.sub(rf"\b{re.escape(eng)}\b", bn, v, flags=re.I)

    # Remove known source-field label fragments if any remain.
    v = re.sub(
        r"\b(?:Additional|Village|Road|Ward|For|Union|Parishod|Porishod|Parishad|Porishad|Mouza|"
        r"Moholla|Mohalla|Upazila|City|Corporation|Municipality|Post|Office|"
        r"Postal|Code|District|Region|Division|Holding|Home|RMO)\b",
        "",
        v, flags=re.I
    )

    # Clean punctuation/spacing left by removals.
    v = re.sub(r"\(\s*\)", "", v)
    v = re.sub(r"\s{2,}", " ", v)
    v = re.sub(r"\s*,\s*", ", ", v)
    v = re.sub(r"\s*-\s*", "-", v)
    v = re.sub(r"\s*:\s*", ": ", v)
    return _line_clean(v)


def _address_from_source(text, heading):
    """
    Extract only the address fields from the source PDF.
    Important: longer labels are matched before shorter labels
    (e.g. Additional Village/Road before Village/Road), so a
    shorter label can never consume the longer label's text.
    """
    t = _norm_address_text(text)

    if heading == "present":
        m = re.search(
            r"Present Address(.*?)(?=Permanent Address|Personal Information|Other Information|$)",
            t, re.I | re.S
        )
    else:
        m = re.search(
            r"Permanent Address(.*?)(?=Education(?:\s|$)|Education Other|Education Sub|Identification|"
            r"Foreign Address|Education|Education Other|Education Sub|Blood Group|TIN|Driving|Passport|Laptop ID|Voter Area|Voter At|$)",
            t, re.I | re.S
        )
    if not m:
        return ""

    block = m.group(1)
    # Remove the RMO label/value region before field parsing.
    # Remove only the RMO field/value. The source can use
    # `City Corporation / Municipality` and `Upozila`, so those are boundaries.
    block = re.sub(
        r"\bRMO\b\s*[:\-]?\s*.*?(?=(?:"
        r"City\s+Corporation\s*/\s*Municipality|"
        r"City\s+Corporation\s+Or\s+Municipality|"
        r"Upazila|Upozila|Upazilla|Upozilla|"
        r"Union/Ward|Mouza/Moholla|Mouza/Mohalla|"
        r"Additional\s+Mouza/Moholla|Additional\s+Mouza/Mohalla|"
        r"Ward\s+For\s+Union|Village/Road|Additional\s+Village/Road|"
        r"Home/Holding|Home\s*/\s*Holding|House\s*/\s*Holding|"
        r"Post\s+Office|Postal\s+Code|District|Region|Division"
        r")\b|$)",
        " ", block, flags=re.I
    )
    block = _norm_address_text(block)

    specs = [
        ("holding", [
            r"Home\s*/\s*Holding\s*(?:No\.?|Number)?",
            r"House\s*/\s*Holding\s*(?:No\.?|Number)?",
            r"Home\s+Holding\s*(?:No\.?|Number)?",
            r"Holding\s*(?:No\.?|Number)?"
        ]),
        ("additional_village", [
            r"Additional\s+Village/Road"
        ]),
        ("village", [
            r"(?<!Additional\s)Village/Road"
        ]),
        ("ward", [
            r"Ward\s+For\s+Union\s+Parishod",
            r"Ward\s+For\s+Union\s+Parishad",
            r"Ward\s+For\s+Union\s+Porishod",
            r"Ward\s+For\s+Union\s+Porishad",
            r"Ward\s+For\s+Union"
        ]),
        ("union", [
            r"Union/Ward"
        ]),
        ("additional_mouza", [
            r"Additional\s+Mouza/Moholla", r"Additional\s+Mouza/Mohalla"
        ]),
        ("mouza", [
            r"(?<!Additional\s)Mouza/Moholla", r"(?<!Additional\s)Mouza/Mohalla"
        ]),
        ("city", [
            r"City\s+Corporation\s+Or\s+Municipality",
            r"City\s+Corporation\s*/?\s*Municipality"
        ]),
        ("upazila", [
            r"Upazila", r"Upozila", r"Upozilla", r"Upazilla"
        ]),
        ("post_office", [
            r"Post\s+Office"
        ]),
        ("postal_code", [
            r"Postal\s+Code"
        ]),
        ("district", [
            r"District"
        ]),
        ("region", [
            r"Region"
        ]),
        ("division", [
            r"Division"
        ]),
    ]

    # Build one combined label regex. Longer alternatives are placed first.
    all_labels = []
    label_to_key = []
    for key, patterns in specs:
        for p in patterns:
            all_labels.append(p)
            label_to_key.append((p, key))
    combined = "|".join(sorted(all_labels, key=len, reverse=True))

    matches = list(re.finditer(combined, block, flags=re.I))
    values = {}
    for i, mm in enumerate(matches):
        key = None
        matched = mm.group(0)
        for p, k in label_to_key:
            if re.fullmatch(p, matched, flags=re.I):
                key = k
                break
        if not key:
            continue

        start = mm.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(block)
        value = _line_clean(block[start:end])

        # Strip common separators and accidental label remnants.
        value = re.sub(r"^[\s:,\-]+", "", value)
        if key == "holding":
            value = re.sub(r"^(?:No\.?|Number)\s*", "", value, flags=re.I)
            value = re.sub(r"^নং\s*", "", value)
        value = _line_clean(value)

        # Never let an English source label survive as a value.
        for bad in [
            "Additional Village/Road", "Village/Road",
            "Additional Mouza/Moholla", "Additional Mouza/Mohalla",
            "Ward For Union Parishod", "Ward For Union Parishad", "Ward For Union Porishod", "Ward For Union Porishad",
            "Union/Ward", "City Corporation Or Municipality",
            "Upazila", "Upozila", "Upozilla", "Upazilla", "Post Office", "Postal Code", "District",
            "Region", "Division"
        ]:
            if value.lower() == bad.lower():
                value = ""
        if value:
            values[key] = value

    # Holding fallback: capture the value after Home/Holding No until the
    # next address label. The value can be Bengali text, not only a number.
    if "holding" not in values:
        hm = re.search(
            r"(?:Home\s*/\s*Holding|House\s*/\s*Holding|Home\s+Holding|Holding)"
            r"\s*(?:No\.?|Number)?\s*[:\-]?\s*(.*?)"
            r"(?=\b(?:Post\s+Office|Postal\s+Code|Region|Division|District|"
            r"Upozila|Upozilla|Upazila|Upazilla|Union/Ward|Mouza/Moholla|"
            r"Additional\s+Mouza/Moholla|Additional\s+Mouza/Mohalla|"
            r"Additional\s+Village/Road|Village/Road|Ward\s+For\s+Union)\b|$)",
            block, flags=re.I | re.S
        )
        if hm:
            val=_line_clean(hm.group(1))
            val=re.sub(r"^(?:No\.?|Number|নং)\s*", "", val, flags=re.I)
            if val:
                values["holding"]=val

    # If the source's primary Village/Road or Mouza/Moholla field is blank
    # but its corresponding Additional field contains the actual address,
    # use that value in the requested standard field so no address data is lost.
    if not values.get("village") and values.get("additional_village"):
        values["village"] = values["additional_village"]
    if not values.get("mouza") and values.get("additional_mouza"):
        values["mouza"] = values["additional_mouza"]

    # Exact screenshot-style labels and serial order.
    # RMO is intentionally omitted.
    labels_bn = {
        "holding": "বাসা/হোল্ডিং",
        "village": "গ্রাম/রাস্তা",
        "additional_village": "অতিরিক্ত গ্রাম/রাস্তা",
        "ward": "ওয়ার্ড",
        "union": "ইউনিয়ন/ওয়ার্ড",
        "mouza": "মৌজা/মহল্লা",
        "additional_mouza": "অতিরিক্ত মৌজা/মহল্লা",
        "upazila": "উপজেলা",
        "city": "সিটি কর্পোরেশন/পৌরসভা",
        "post_office": "পোস্ট অফিস",
        "postal_code": "পোস্ট কোড",
        "district": "জেলা",
        "region": "অঞ্চল",
        "division": "বিভাগ",
    }

    order = [
        "holding", "village", "mouza", "union", "ward",
        "post_office", "postal_code", "upazila",
        "district", "region", "division"
    ]

    parts = []
    for key in order:
        value = _line_clean(values.get(key, ""))
        if value:
            value = _address_bangla_only(value)
        if not value:
            if key == "holding" and re.search(
                r"(?:Home\s*/\s*Holding|House\s*/\s*Holding)\s*(?:No\.?|Number)?\s*[-–—]",
                block, flags=re.I
            ):
                value = "-"
            else:
                continue

        # The screenshot uses Arabic digits for ward but Bengali digits for
        # postal code. Keep ward as extracted; Bengali digits for postal code.
        if key == "postal_code":
            value = _bangla_digits(value)

        parts.append(f"{labels_bn[key]}: {value}")

    # If Holding has no source value, omit it completely rather than showing
    # an empty label. All present fields remain one comma-separated paragraph.
    result = ", ".join(parts) + ("।" if parts else "")
    # Last-resort protection against any English structural text leaking into
    # the final address paragraph.
    result = re.sub(
        r"\b(?:Additional|Village|Road|Ward|For|Union|Parishod|Porishod|Parishad|Porishad|Mouza|"
        r"Moholla|Mohalla|Upazila|City|Corporation|Municipality|Post|Office|"
        r"Postal|Code|District|Region|Division|Holding|Home|RMO)\b",
        "",
        result, flags=re.I
    )
    result = re.sub(r"\s{2,}", " ", result)
    result = re.sub(r"\s*,\s*", ", ", result)
    return result

def parse_text(text, address_text=None):
    """
    Parse report fields from the supplied source text.
    `text` may contain all source pages for fields such as Form No, Serial No,
    Voter Area and Education. Address fields are deliberately parsed from
    `address_text` (page 1) so page-2 data cannot leak into an address.
    """
    d = {k: "" for k in FIELDS}

    def get(patterns):
        return first(text, patterns)

    # These fields are often present on a later source page, so search all
    # source pages for them.
    d["form_no"] = get([
        r"ফরম\s*(?:নম্বর|নং)?\s*[:\-]?\s*([0-9A-Za-z_-]{1,40})",
        r"\bForm\s*(?:No\.?|Number)\s*[:\-]?\s*([0-9A-Za-z_-]{1,40})",
        r"\bForm\s*(?:No\.?|Number)\s*[:\-]?\s*\n?\s*([0-9A-Za-z_-]{1,40})",
        r"\bForm\s*[:\-]?\s*([0-9A-Za-z_-]{1,40})",
        r"\bForm\s*(?:No\.?|Number)?\s+([0-9A-Za-z_-]{1,40})",
    ])
    d["serial_no"] = get([
        r"\bSl\s*(?:No\.?|Number)\s*[:\-]?\s*([0-9]{1,30})",
        r"\bS[\s\-]*l\s*(?:No\.?|Number)\s*[:\-]?\s*([0-9]{1,30})",
        r"সিরিয়াল\s*(?:নম্বর|নং)?\s*[:\-]?\s*([0-9]{1,30})",
        r"সিরিয়াল\s*(?:নম্বর|নং)?\s*[:\-]?\s*([0-9]{1,30})",
        r"\bSerial\s*(?:No\.?|Number)\s*[:\-]?\s*([0-9]{1,30})",
        r"\bSerial\s*(?:No\.?|Number)\s*[:\-]?\s*\n?\s*([0-9]{1,30})",
        r"\bSerial\s*[:\-]?\s*([0-9]{1,30})",
        r"\bSerial\s*(?:No\.?|Number)?\s+([0-9]{1,30})",
    ])
    d["education"] = get([
        r"\bEducational\s+Qualification\s*[:\-]?\s*([^\r\n]+)",
        r"\bEducation\s*[:\-]?\s*([^\r\n]+)",
        r"\bEducation\s+Other\s+Education\s+Sub\s*[:\-]?\s*([^\r\n]+)",
    ])

    d["national_id"] = get([r"\bNational\s+ID\s*[:\-]?\s*([0-9]{8,20})"])
    d["pin"] = get([r"\bPin\s*[:\-]?\s*([0-9]{8,30})"])
    d["voter_no"] = get([r"\bVoter\s+No\s*[:\-]?\s*([0-9]{6,20})"])
    d["voter_area"] = get([
        r"\bVoter\s+Area\s*[:\-]?\s*([^\r\n]+)",
        r"\bVoter\s+Area\s+Name\s*[:\-]?\s*([^\r\n]+)",
    ])
    d["voter_at"] = get([r"\bVoter\s+At\s*[:\-]?\s*([^\r\n]+)"])

    d["name_bn"] = get([
        r"Name\s*\(\s*Bangla\s*\)\s*[:\-]?\s*([^\r\n]+)",
        r"Name\(Bangla\)\s*[:\-]?\s*([^\r\n]+)"
    ])
    d["name_en"] = get([
        r"Name\s*\(\s*English\s*\)\s*[:\-]?\s*([^\r\n]+)",
        r"Name\(English\)\s*[:\-]?\s*([^\r\n]+)"
    ])
    d["dob"] = get([r"\bDate\s+of\s+Birth\s*[:\-]?\s*([0-9]{4}-[0-9]{2}-[0-9]{2})"])
    d["birth_place"] = get([r"\bBirth\s+Place\s*[:\-]?\s*([^\r\n]+)"])
    d["father"] = get([r"\bFather(?:\s+Name)?\s*[:\-]?\s*([^\r\n]+)"])
    d["mother"] = get([r"\bMother(?:\s+Name)?\s*[:\-]?\s*([^\r\n]+)"])
    d["spouse"] = get([r"\bSpouse(?:\s+Name)?\s*[:\-]?\s*([^\r\n]+)"])
    d["gender"] = get([r"\bGender\s*[:\-]?\s*([^\r\n]+)"])
    d["occupation"] = get([r"\bOccupation\s*[:\-]?\s*([^\r\n]+)"])
    d["blood_group"] = get([r"\bBlood\s+Group\s*[:\-]?\s*([^\r\n]+)"])
    # A blank source field can make PDF text extraction attach the next label
    # to it. Never treat a structural label as a real value.
    if d["spouse"].strip().lower() in {
        "gender", "occupation", "blood group", "tin", "education",
        "education other", "education sub", "identification"
    }:
        d["spouse"] = ""
    if d["blood_group"].strip().lower() in {
        "tin", "driving", "passport", "laptop id", "nid father",
        "nid mother", "nid spouse", "voter no father", "voter no mother",
        "voter no spouse", "phone", "mobile", "email", "religion"
    }:
        d["blood_group"] = ""

    # Only page 1 is allowed to supply addresses.
    addr_text = address_text if address_text is not None else text
    d["present_address"] = _address_from_source(addr_text, "present")
    d["permanent_address"] = _address_from_source(addr_text, "permanent")
    return d

def extract_photo(pdf_path):
    doc=fitz.open(pdf_path)
    candidates=[]
    for pi,page in enumerate(doc):
        for info in page.get_image_info(xrefs=True):
            xref=info.get("xref")
            if not xref: continue
            w,h=info.get("width",0),info.get("height",0)
            if w<80 or h<80: continue
            ratio=w/h
            # Portrait-ish images are preferred as the photo.
            score=(1 if 0.45 <= ratio <= 0.9 else 0) + min(w*h/300000,2)
            candidates.append((score,pi,xref,w,h))
    if not candidates: return ""
    candidates.sort(reverse=True)
    _,pi,xref,w,h=candidates[0]
    try:
        pix=fitz.Pixmap(doc,xref)
        if pix.alpha: pix=fitz.Pixmap(fitz.csRGB,pix)
        img=Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
        img.thumbnail((500,700))
        buf=io.BytesIO(); img.save(buf,"JPEG",quality=90)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""

def make_qr(name_en, national_id="", dob=""):
    # QR contains English name, NID number and date of birth only.
    # Each item is on its own line; no commas/separators are added.
    payload = "\n".join([
        str(name_en or "").strip(),
        str(national_id or "").strip(),
        str(dob or "").strip(),
    ])
    qr = qrcode.QRCode(version=None, box_size=8, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image().convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return base64.b64encode(buf.getvalue()).decode()


def pdf_filename(nid):
    nid = re.sub(r"[^0-9A-Za-z_-]", "", str(nid or ""))
    return f"V1_{nid}.pdf" if nid else "V1_unknown.pdf"

def esc(v):
    return html.escape(str(v or ""))

def find_browser():
    candidates = [
        os.environ.get("CHROME_PATH",""),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        shutil.which("chrome"),
        shutil.which("msedge"),
        shutil.which("google-chrome"),
        shutil.which("chromium"),
    ]
    for p in candidates:
        if p and Path(p).exists():
            return p
    return None

def _find_browser():
    """Find Chrome/Edge on Windows, then common Linux/macOS paths."""
    candidates = []
    if platform.system() == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        program = os.environ.get("PROGRAMFILES", "")
        program_x86 = os.environ.get("PROGRAMFILES(X86)", "")
        candidates += [
            os.path.join(local, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(program, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(program_x86, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(program, r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(program_x86, r"Microsoft\Edge\Application\msedge.exe"),
        ]
    candidates += [
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"
    ]
    for c in candidates:
        if os.path.isabs(c):
            if os.path.exists(c):
                return c
        else:
            p = shutil.which(c)
            if p:
                return p
    return None

_BG_DATA_CACHE = {"key": None, "data": ""}

def selected_background_data_url():
    """Return the selected background directly from the production DB.

    Render's local filesystem is ephemeral: after a sleeping instance wakes
    up (or a new instance is created), files written under /app/data can be
    gone. The actual selected background is therefore read from
    ``web_backgrounds`` in the production database on every PDF request.
    A local copy is still restored as a convenience/cache, but PDF generation
    never depends on that local copy existing.
    """
    bg = get_default_background_db()
    if not bg:
        return ""

    name = Path(str(bg.get("name") or "background.jpg")).name
    mime = str(bg.get("mime") or "")
    data_b64 = str(bg.get("data") or "")

    if not data_b64 or not mime:
        return ""

    # Cache by the stored background content. This avoids repeatedly decoding
    # the same image during a single running instance while still picking up
    # a new image immediately after the admin changes it.
    key = (name, mime, data_b64)
    if _BG_DATA_CACHE["key"] == key:
        return _BG_DATA_CACHE["data"]

    try:
        raw = base64.b64decode(data_b64)
        data_url = f"data:{mime};base64,{base64.b64encode(raw).decode()}"
        _BG_DATA_CACHE["key"] = key
        _BG_DATA_CACHE["data"] = data_url

        # Restore the ephemeral local copy too. If Render has restarted, this
        # recreates the file automatically from the persistent DB.
        try:
            BACKGROUNDS.mkdir(exist_ok=True)
            local_path = BACKGROUNDS / name
            if not local_path.exists() or local_path.read_bytes() != raw:
                local_path.write_bytes(raw)
            set_setting_str("background_image", name)
        except Exception:
            pass

        return data_url
    except Exception:
        return ""



_MONTH_NAMES = [
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]
_ORDINALS = {
    1:"First",2:"Second",3:"Third",4:"Fourth",5:"Fifth",6:"Sixth",7:"Seventh",
    8:"Eighth",9:"Ninth",10:"Tenth",11:"Eleventh",12:"Twelfth",13:"Thirteenth",
    14:"Fourteenth",15:"Fifteenth",16:"Sixteenth",17:"Seventeenth",18:"Eighteenth",
    19:"Nineteenth",20:"Twentieth",21:"Twenty-first",22:"Twenty-second",
    23:"Twenty-third",24:"Twenty-fourth",25:"Twenty-fifth",26:"Twenty-sixth",
    27:"Twenty-seventh",28:"Twenty-eighth",29:"Twenty-ninth",30:"Thirtieth",31:"Thirty-first"
}
_UNDER_100 = [
    "Zero","One","Two","Three","Four","Five","Six","Seven","Eight","Nine","Ten",
    "Eleven","Twelve","Thirteen","Fourteen","Fifteen","Sixteen","Seventeen",
    "Eighteen","Nineteen"
]
_TENS = {20:"Twenty",30:"Thirty",40:"Forty",50:"Fifty",60:"Sixty",70:"Seventy",80:"Eighty",90:"Ninety"}

def _english_number(n: int) -> str:
    if n < 20:
        return _UNDER_100[n]
    if n < 100:
        return _TENS[n] if n % 10 == 0 else _TENS[n - n % 10] + "-" + _UNDER_100[n % 10].lower()
    if n < 1000:
        return _UNDER_100[n // 100] + " Hundred" + ((" " + _english_number(n % 100)) if n % 100 else "")
    if n < 1000000:
        return _english_number(n // 1000) + " Thousand" + ((" " + _english_number(n % 1000)) if n % 1000 else "")
    return str(n)

def birth_dob_in_words(dob: str) -> str:
    try:
        dt = datetime.strptime(str(dob).strip(), "%Y-%m-%d")
        return f"{_ORDINALS[dt.day]} of {_MONTH_NAMES[dt.month]} {_english_number(dt.year)}"
    except Exception:
        return ""

def _birth_date_display(value: str) -> str:
    value = str(value or "").strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(value, fmt).strftime("%d/%m/%Y")
        except Exception:
            pass
    return value

def make_birth_reference_pdf(d, background_b64="", background_mime="image/jpeg"):
    """Create a clearly marked, user-supplied birth-data reference PDF.
    No BDRIS scraping, CAPTCHA automation, or government-record retrieval occurs.
    """
    job = uuid.uuid4().hex[:12]
    safe_no = re.sub(r"[^0-9A-Za-z_-]", "", str(d.get("birth_reg_no") or "birth-reference")) or "birth-reference"
    out = GENERATED / f"Birth_Reference_{safe_no}_{job}.pdf"
    html_path = GENERATED / f"birth_render_{job}.html"

    # QR points only to the public verification homepage; it does not contain
    # scraped government data or an impersonating verification payload.
    qr_data = "https://bdris.gov.bd/certificate/verify?key=+QDbLK8/T8bcCO18QL+ijIW10etKS9wimz/T5Eggfs0DXLBhP2DYrM67+A+rX3g4"
    qr_bytes = io.BytesIO()
    qrcode.make(qr_data, box_size=7, border=1).save(qr_bytes, format="PNG")
    qr_b64 = base64.b64encode(qr_bytes.getvalue()).decode()
    ref_code = ''.join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(5))

    bg_html = ""
    if background_b64:
        bg_html = f'<img class="page-bg" src="data:{background_mime};base64,{background_b64}">'
    else:
        bg = selected_background_data_url()
        if bg:
            bg_html = f'<img class="page-bg" src="{bg}">'

    dob_words = str(d.get("dob_words") or "").strip() or birth_dob_in_words(d.get("dob", ""))
    dob = _birth_date_display(d.get("dob", ""))
    reg_date = _birth_date_display(d.get("date_of_registration", ""))
    issue_date = _birth_date_display(d.get("date_of_issuance", ""))

    def cell(label_bn, label_en, value):
        return (
            f'<div class="bi-label"><div class="bn">{esc(label_bn)}</div><div class="en">{esc(label_en)}</div></div>'
            f'<div class="bi-value">{esc(value)}</div>'
        )

    html_doc = f"""<!doctype html>
<html lang="bn"><head><meta charset="utf-8">
<style>
@font-face {{font-family:Bangla;src:url('file://{FONT.as_posix()}');font-weight:400;}}
@font-face {{font-family:Bangla;src:url('file://{FONT_SEMIBOLD.as_posix()}');font-weight:700;}}
@page {{size:A4;margin:0;}}
* {{box-sizing:border-box;box-shadow:none!important;text-shadow:none!important;}}
html,body {{margin:0;padding:0;width:210mm;height:297mm;}}
body {{font-family:"SolaimanLipi","SutonnyMJ",Bangla,Arial,sans-serif;color:#111;background:transparent;font-size:10.7pt;line-height:1.18;-webkit-font-smoothing:antialiased;text-shadow:none!important;box-shadow:none!important;}}
* {{text-shadow:none!important;box-shadow:none!important;}}
.page-bg {{position:fixed;left:0;top:0;width:210mm;height:297mm;object-fit:cover;z-index:-2;}}
.page {{position:relative;width:210mm;height:297mm;padding:0;}}
.content {{position:absolute;left:25.4mm;right:18mm;top:0;bottom:14mm;background:transparent;}}
.qr-block {{position:absolute;left:-7.62mm;top:30.48mm;width:32mm;text-align:center;}}
.qr {{width:30.48mm;height:30.48mm;display:block;margin:0 auto;}}
.ref {{font-family:Arial,sans-serif;font-weight:700;font-size:9pt;letter-spacing:1.8px;margin-top:1.5mm;}}
.head {{position:absolute;left:8mm;right:0;top:50.8mm;text-align:center;}}
.office {{display:none!important;}}
.office-bn {{font-family:"SolaimanLipi","SutonnyMJ",Bangla,Arial,sans-serif;font-size:9.5pt;font-weight:400;margin-top:1.8mm;white-space:nowrap;}}
.rule {{font-family:Arial,sans-serif;font-size:9pt;margin-top:2.2mm;}}
.title {{font-size:12.5pt;font-weight:700;margin-top:2.2mm;white-space:nowrap;}}
.notice {{display:none !important;}}
.grid-top {{position:absolute;left:0;right:0;top:93mm;display:grid;grid-template-columns:1fr 1.25fr 1fr;column-gap:7mm;font-family:"SolaimanLipi","SutonnyMJ",Bangla,Arial,sans-serif;}}
.top-item {{font-size:8.5pt;}}
.top-item.center {{text-align:center;}}
.top-label {{font-weight:700;}}
.top-value {{margin-top:1.5mm;font-size:10.8pt;}}
.top-item.center .top-label,.top-item.center .top-value {{font-weight:700;font-size:11.2pt;}}
.bio {{position:absolute;left:0;right:0;top:111mm;}}
.bio-row {{display:grid;grid-template-columns:38mm 1fr 31mm 1.15fr;min-height:11mm;align-items:start;}}
.bio-row + .bio-row.dob-word {{margin-top:-3mm;}}
.bio-row.single {{grid-template-columns:38mm 1fr 31mm 1.15fr;}}
.bio-label {{font-weight:400;padding:2.3mm 1.5mm 1.5mm 0;display:grid;grid-template-columns:minmax(0,1fr) 3.5mm;column-gap:1mm;align-items:start;}}.bio-label .label-text {{min-width:0;}}.bio-label .colon {{text-align:center;width:3.5mm;}}
.bio-value {{padding:2.3mm 2mm 1.5mm 0;overflow-wrap:anywhere;}}
.bio-value.en {{font-family:Arial,sans-serif;}}
.addr {{margin-top:2mm;display:grid;grid-template-columns:38mm 1fr 31mm 1.15fr;min-height:25mm;}}
.addr .bio-value {{white-space:pre-wrap;line-height:1.35;}}
.bottom-note {{position:absolute;left:0;right:0;bottom:3mm;text-align:center;font-family:Arial,sans-serif;font-size:6.8pt;color:#555;}}
.watermark {{position:absolute;left:0;right:0;bottom:2.5mm;text-align:center;font-family:Arial,sans-serif;font-size:5.5pt;font-weight:600;color:rgba(70,70,70,.75);transform:none;pointer-events:none;}}
</style></head>
<body>
{bg_html}
<div class="page">
  <div class="content">
    <div class="qr-block">
      <img class="qr" src="data:image/png;base64,{qr_b64}">
      <div class="ref">{ref_code}</div>
    </div>

    <div class="head">
      <div class="office-bn">{esc(d.get("union_en",""))}</div>
      <div class="office-bn">{esc(d.get("upazila_district_en",""))}</div>
      <div class="rule">(Rule 9, 10)</div>
      <div class="title">জন্ম নিবন্ধন সনদ / Birth Registration Certificate</div>
    </div>

    <div class="grid-top">
      <div class="top-item">
        <div class="top-label">Date of Registration</div>
        <div class="top-value">{esc(reg_date)}</div>
      </div>
      <div class="top-item center">
        <div class="top-label">Birth Registration Number</div>
        <div class="top-value">{esc(d.get("birth_reg_no",""))}</div>
      </div>
      <div class="top-item center">
        <div class="top-label">Date of Issuance</div>
        <div class="top-value">{esc(issue_date)}</div>
      </div>
    </div>

    <div class="bio">
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">জন্ম তারিখ</span><span class="colon">:</span></div><div class="bio-value">{esc(dob)}</div>
        <div class="bio-label"><span class="label-text">Sex</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("sex",""))}</div>
      </div>
      <div class="bio-row dob-word">
        <div class="bio-label"><span class="label-text">In Word</span><span class="colon">:</span></div><div class="bio-value en" style="font-style:italic;white-space:nowrap;font-size:8.6pt;letter-spacing:-.05px">{esc(dob_words)}</div>
        <div></div><div></div>
      </div>
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">নাম</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("name_bn",""))}</div>
        <div class="bio-label"><span class="label-text">Name</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("name_en",""))}</div>
      </div>
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">মাতা</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("mother",""))}</div>
        <div class="bio-label"><span class="label-text">Mother</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("mother_en",""))}</div>
      </div>
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">মাতার জাতীয়তা</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("mother_nationality_bn", d.get("nationality","Bangladeshi")))}</div>
        <div class="bio-label"><span class="label-text">Nationality</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("mother_nationality_en", d.get("nationality","Bangladeshi")))}</div>
      </div>
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">পিতা</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("father",""))}</div>
        <div class="bio-label"><span class="label-text">Father</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("father_en", d.get("father","")))}</div>
      </div>
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">পিতার জাতীয়তা</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("father_nationality_bn", d.get("nationality","Bangladeshi")))}</div>
        <div class="bio-label"><span class="label-text">Nationality</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("father_nationality_en", d.get("nationality","Bangladeshi")))}</div>
      </div>
      <div class="bio-row">
        <div class="bio-label"><span class="label-text">জন্মস্থান</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("birth_place_bn", d.get("birth_place","")))}</div>
        <div class="bio-label"><span class="label-text">Place of Birth</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("birth_place_en", d.get("birth_place","")))}</div>
      </div>
      <div class="addr">
        <div class="bio-label"><span class="label-text">স্থায়ী ঠিকানা</span><span class="colon">:</span></div><div class="bio-value">{esc(d.get("permanent_bn",""))}</div>
        <div class="bio-label"><span class="label-text">Permanent Address</span><span class="colon">:</span></div><div class="bio-value en">{esc(d.get("permanent_en",""))}</div>
      </div>
    </div>

  </div>
</div>
</body></html>"""

    if WeasyHTML is not None:
        try:
            WeasyHTML(string=html_doc, base_url=str(BASE)).write_pdf(str(out))
            if out.exists() and out.stat().st_size >= 1000:
                return out
        except Exception as e:
            print("BIRTH REFERENCE WEASY ERROR:", repr(e))

    browser = _find_browser()
    if not browser:
        raise HTTPException(500, "PDF renderer is unavailable.")
    html_path.write_text(html_doc, encoding="utf-8")
    cmd=[browser,"--headless=new","--disable-gpu","--no-sandbox","--disable-extensions","--disable-dev-shm-usage","--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-sync","--no-pdf-header-footer",f"--print-to-pdf={str(out)}",html_path.resolve().as_uri()]
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=45)
    if result.returncode!=0 or not out.exists() or out.stat().st_size<1000:
        cmd[1]="--headless"
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=45)
    if result.returncode!=0 or not out.exists() or out.stat().st_size<1000:
        raise HTTPException(500,(result.stderr or result.stdout or "PDF generation failed")[-1200:])
    return out

def make_pdf(d):
    job = uuid.uuid4().hex[:12]
    out = GENERATED / f"V1_{re.sub(r'[^0-9A-Za-z_-]', '', d.get('national_id','report'))}.pdf"
    html_path = GENERATED / f"render_{job}.html"

    photo = (
        f'<img class="photo" src="data:image/jpeg;base64,{d.get("photo_b64","")}">'
        if d.get("photo_b64") else '<div class="photo empty">ছবি</div>'
    )
    photo_name = f'<div class="photo-name">{esc(d.get("name_en",""))}</div>' if d.get("name_en") else ""
    qr = (
        f'<img class="qr" src="data:image/png;base64,{d.get("qr_b64","")}">'
        if d.get("qr_b64") else ""
    )
    bg = selected_background_data_url()
    bg_html = f'<img class="page-bg" src="{bg}">' if bg else ""

    def row(label, value):
        return f'<tr><td class="label">{esc(label)}</td><td class="value">{esc(value)}</td></tr>'

    national_rows = "".join([
        row("জাতীয় পরিচয়পত্র নম্বর", d.get("national_id")),
        row("পিন নম্বর", d.get("pin")),
        row("ভোটার নম্বর", d.get("voter_no")),
        row("ফরম নম্বর", d.get("form_no")),
        row("সিরিয়াল নম্বর", d.get("serial_no")),
        row("ভোটার এরিয়া", d.get("voter_area")),
    ])
    personal_rows = "".join([
        row("নাম (বাংলা)", d.get("name_bn")),
        row("নাম (ইংরেজী)", d.get("name_en")),
        row("জন্ম তারিখ", d.get("dob")),
        row("পিতার নাম", d.get("father")),
        row("মাতার নাম", d.get("mother")),
        row("স্বামী/স্ত্রীর নাম", d.get("spouse")),
    ])
    other_rows = "".join([
        row("লিঙ্গ", d.get("gender")),
        row("শিক্ষাগত যোগ্যতা", d.get("education")),
        row("পেশা", d.get("occupation")),
        row("রক্তের গ্রুপ", d.get("blood_group")),
        row("জন্মস্থান", d.get("birth_place")),
    ])

    html_doc = f"""<!doctype html>
<html lang="bn">
<head>
<meta charset="utf-8">
<style>
@font-face {{
  font-family: Bangla;
  src: url('file://{FONT.as_posix()}');
  font-weight:300;
}}
@font-face {{
  font-family: Bangla;
  src: url('file://{FONT_REGULAR.as_posix()}');
  font-weight:400;
}}
@font-face {{
  font-family: Bangla;
  src: url('file://{FONT_SEMIBOLD.as_posix()}');
  font-weight:600;
}}
@page {{ size:A4; margin:0; }}
* {{ box-sizing:border-box; text-shadow:none !important; box-shadow:none !important; -webkit-text-stroke:0 !important; }}
body {{ font-family:"SolaimanLipi","SutonnyMJ",Bangla,sans-serif; color:#111; font-size:13px; font-weight:400; line-height:1.24; -webkit-font-smoothing:antialiased; text-shadow:none !important; margin:0; padding:2.5in 0.8in 1.2in 2.5in; }}
.header, .notice, .section, table, .address, .footer {{ background:rgba(255,255,255,.96); border:0 !important; box-shadow:none !important; text-shadow:none !important; }}
.page-bg {{ position:fixed; left:0; top:0; width:210mm; height:297mm; object-fit:fill; opacity:1; z-index:0; pointer-events:none; }}
.report-content {{ position:relative; z-index:1; }}
.header {{ padding:7px 10px; text-align:center; margin-bottom:7px; }}
h1 {{ margin:0; font-size:19px; }}
.sub {{ font-size:8px; font-weight:bold; margin-top:2px; }}
.notice {{ margin:5px 0 8px; padding:4px 7px; text-align:center; font-size:8px; font-weight:bold; }}
.top {{ display:block; position:relative; }}
.media {{ position:fixed; left:0; top:92mm; width:71.12mm; display:flex; flex-direction:column; align-items:center; z-index:2; }}
.photo-name {{ margin-top:2mm; font-family:"Segoe UI","Arial",sans-serif; font-size:14px; font-weight:700; text-align:center; max-width:43.18mm; word-break:break-word; letter-spacing:.1px; }}
.photo {{ width:30.48mm; height:auto; max-height:none; object-fit:contain; border:0.6pt solid #777; border-radius:2.2mm; }}
.empty {{ display:flex; align-items:center; justify-content:center; }}
.qr {{ width:25.4mm; height:25.4mm; margin-top:4mm; }}
.section {{ margin-top:3px; margin-bottom:1px; background:#c2e4eb; border:0 !important; padding:4px 8px; font-size:17px; font-weight:700; line-height:1.18; }}
table {{ width:100%; border-collapse:collapse; }}
td {{ border:0.08pt solid rgba(0,0,0,.08) !important; padding:3px 5px; vertical-align:top; background:transparent !important; box-shadow:none !important; text-shadow:none !important; }}
.label {{ width:35.5%; font-weight:400; font-size:13px; line-height:1.32; -webkit-font-smoothing:antialiased; background:transparent !important; border:0.08pt solid rgba(0,0,0,.08) !important; }}
.value {{ background:transparent !important; border:0.08pt solid rgba(0,0,0,.08) !important; font-weight:400; box-shadow:none !important; }}
.address {{ border:0.08pt solid rgba(0,0,0,.08) !important; padding:4px 6px; line-height:1.40; font-weight:400; min-height:0; margin-bottom:3px; overflow-wrap:anywhere; word-break:break-word; background:#fff; }}
.footer {{ margin-top:8px; padding-top:4px; text-align:center; font-size:8px; font-weight:600; }}
</style>
</head>
<body>
{bg_html}
<div class="report-content">
<div class="header">
  <h1></h1>
  
</div>



<div class="top">
  <div class="media">{photo}{photo_name}{qr}</div>
  <div>
    <div class="section" style="margin-top:0">জাতীয় পরিচিতি তথ্য</div>
    <table>{national_rows}</table>

    <div class="section">ব্যক্তিগত তথ্য</div>
    <table>{personal_rows}</table>

    <div class="section">অন্যান্য তথ্য</div>
    <table>{other_rows}</table>
  </div>
</div>

<div class="section">বর্তমান ঠিকানা</div>
<div class="address">{esc(d.get("present_address"))}</div>

<div class="section">স্থায়ী ঠিকানা</div>
<div class="address">{esc(d.get("permanent_address"))}</div>


</div>
</body>
</html>"""

    # Optional fast path: if WeasyPrint is installed, use it in-process.
    # On Render/free deployments it may not be installed, so we MUST fall
    # back cleanly to the existing Chromium renderer instead of crashing
    # during application import.
    if WeasyHTML is not None:
        try:
            WeasyHTML(
                string=html_doc,
                base_url=str(BASE)
            ).write_pdf(str(out))

            if out.exists() and out.stat().st_size >= 1000:
                return out
            raise RuntimeError("WeasyPrint produced an empty PDF")
        except Exception as fast_error:
            print("FAST PDF RENDER ERROR:", repr(fast_error))

    browser = _find_browser()
    if not browser:
        raise HTTPException(500, "PDF renderer is unavailable.")

    html_path.write_text(html_doc, encoding="utf-8")

    cmd = [
        browser, "--headless=new", "--disable-gpu", "--no-sandbox",
        "--disable-extensions", "--disable-dev-shm-usage",
        "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--disable-sync",
        "--disable-translate", "--no-pdf-header-footer",
        "--run-all-compositor-stages-before-draw", "--virtual-time-budget=50",
        f"--print-to-pdf={str(out)}", html_path.resolve().as_uri()
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode != 0 or not out.exists() or out.stat().st_size < 1000:
            cmd[1] = "--headless"
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)

        if result.returncode != 0 or not out.exists() or out.stat().st_size < 1000:
            raise HTTPException(
                500,
                (result.stderr or result.stdout or "PDF generation failed")[-1200:]
            )

        return out
    finally:
        try:
            html_path.unlink(missing_ok=True)
        except Exception:
            pass


# -------------------------- Customer/Admin web API --------------------------

@app.post("/api/auth/login")
def web_login(email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    with prod_engine.begin() as c:
        r = c.execute(text(
            "SELECT id,email,password_hash,role,active FROM web_users WHERE email=:e"
        ), {"e": email}).mappings().first()
    if not r or not r["active"] or not _verify_password(password, r["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    token = _token(int(r["id"]), r["role"])
    out = JSONResponse({"success": True, "email": r["email"], "role": r["role"]})
    out.set_cookie("web_session", token, httponly=True, secure=False, samesite="lax", max_age=86400*7)
    return out

@app.post("/api/auth/logout")
def web_logout():
    out = JSONResponse({"success": True})
    out.delete_cookie("web_session")
    return out
@app.post("/api/auth/register")
def web_register(
    full_name: str = Form(...),
    email: str = Form(...),
    mobile: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    full_name = full_name.strip()
    email = email.strip().lower()
    mobile = mobile.strip()

    if not full_name or not email or not mobile:
        raise HTTPException(400, "All fields are required")

    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    if password != confirm_password:
        raise HTTPException(400, "Passwords do not match")

    with prod_engine.begin() as c:
        if c.execute(
            text("SELECT id FROM web_users WHERE email=:e"),
            {"e": email}
        ).fetchone():
            raise HTTPException(409, "Email already registered")

        uid = _next_id(c, "web_users")

        c.execute(
            text("""
                INSERT INTO web_users
                (id,email,password_hash,role,active,created_at,full_name,mobile)
                VALUES
                (:id,:e,:p,'customer',1,:t,:n,:m)
            """),
            {
                "id": uid,
                "e": email,
                "p": _hash_password(password),
                "t": datetime.utcnow().isoformat(),
                "n": full_name,
                "m": mobile
            }
        )

        c.execute(
            text("INSERT INTO web_wallets(user_id,credits) VALUES(:u,0)"),
            {"u": uid}
        )

    token = _token(int(uid), "customer")
    out = JSONResponse({
        "success": True,
        "message": "Account created successfully",
        "email": email,
        "role": "customer"
    })
    # Newly registered customers are active immediately and are logged in
    # automatically. No admin activation step is required.
    out.set_cookie(
        "web_session",
        token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=86400 * 7
    )
    return out

@app.get("/api/auth/me")
def web_me(web_session: str | None = Cookie(default=None)):
    u = current_user(web_session)
    return {"success":True, "user":{"id":u["id"],"email":u["email"],"role":u["role"]}, "balance":prod_balance(u["id"])}


@app.get("/api/admin/price")
def admin_web_price_get(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    sign_price = int(prod_setting("sign_to_server_price", prod_setting("web_price", "1")))
    birth_price = int(prod_setting("auto_birth_price", "1"))
    api_price = int(prod_setting("api_price", "1"))
    voter_price = int(prod_setting("voter_search_price", "1"))
    return {
        "success": True,
        "web_price": sign_price,
        "sign_to_server_price": sign_price,
        "auto_birth_price": birth_price,
        "api_price": api_price,
        "voter_search_price": voter_price
    }

# ---------------------------------------------------------------------------
# Admin/public/section messages. Public message is available without login;
# section messages are returned after login and shown only on their section.
# ---------------------------------------------------------------------------
SECTION_MESSAGE_KEYS = (
    "message_sign_to_server", "message_voter_search", "message_auto_birth",
    "message_buy_credits", "message_payment_history", "message_history",
    "message_profile", "message_customer_data"
)

@app.get("/api/public-message")
def public_message():
    return {"success": True, "message": prod_setting("public_message", "")}

@app.get("/api/customer/messages")
def customer_messages(web_session: str | None = Cookie(default=None)):
    require_customer(web_session)
    return {"success": True, "messages": {
        "public": prod_setting("public_message", ""),
        "sign_to_server": prod_setting("message_sign_to_server", ""),
        "voter_search": prod_setting("message_voter_search", ""),
        "auto_birth": prod_setting("message_auto_birth", ""),
        "buy_credits": prod_setting("message_buy_credits", ""),
        "payment_history": prod_setting("message_payment_history", ""),
        "history": prod_setting("message_history", ""),
        "profile": prod_setting("message_profile", ""),
        "customer_data": prod_setting("message_customer_data", "")
    }}

@app.get("/api/admin/messages")
def admin_messages_get(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    return {"success": True, "messages": {
        "public": prod_setting("public_message", ""),
        "sign_to_server": prod_setting("message_sign_to_server", ""),
        "voter_search": prod_setting("message_voter_search", ""),
        "auto_birth": prod_setting("message_auto_birth", ""),
        "buy_credits": prod_setting("message_buy_credits", ""),
        "payment_history": prod_setting("message_payment_history", ""),
        "history": prod_setting("message_history", ""),
        "profile": prod_setting("message_profile", ""),
        "customer_data": prod_setting("message_customer_data", "")
    }}

@app.post("/api/admin/messages")
def admin_messages_save(
    public: str = Form(""),
    sign_to_server: str = Form(""),
    voter_search: str = Form(""),
    auto_birth: str = Form(""),
    buy_credits: str = Form(""),
    payment_history: str = Form(""),
    history: str = Form(""),
    profile: str = Form(""),
    customer_data: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    values = {
        "public_message": public,
        "message_sign_to_server": sign_to_server,
        "message_voter_search": voter_search,
        "message_auto_birth": auto_birth,
        "message_buy_credits": buy_credits,
        "message_payment_history": payment_history,
        "message_history": history,
        "message_profile": profile,
        "message_customer_data": customer_data,
    }
    for key, value in values.items():
        value = str(value or "").strip()
        if len(value) > 1000:
            raise HTTPException(400, f"{key} message must be 1000 characters or fewer")
        prod_set_setting(key, value)
    return {"success": True, "message": "All messages saved successfully."}

@app.get("/api/support")
def support_info():
    """Public support information. The WhatsApp group link is safe to expose publicly."""
    return {"success": True, "whatsapp_group_link": prod_setting("whatsapp_group_link", "")}

@app.get("/api/admin/support")
def admin_support_get(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    return {"success": True, "whatsapp_group_link": prod_setting("whatsapp_group_link", "")}

@app.post("/api/admin/support")
def admin_support_save(
    whatsapp_group_link: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    link = str(whatsapp_group_link or "").strip()
    if len(link) > 500:
        raise HTTPException(400, "WhatsApp group link must be 500 characters or fewer")
    if link and not re.match(r"^https://[^\s]+$", link, re.I):
        raise HTTPException(400, "WhatsApp group link must be a valid HTTPS URL")
    prod_set_setting("whatsapp_group_link", link)
    return {"success": True, "whatsapp_group_link": link, "message": "WhatsApp group link saved successfully."}

@app.get("/api/admin/announcement")
def admin_announcement_get(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    return {"success": True, "message": prod_setting("public_message", "")}

@app.post("/api/admin/announcement")
def admin_announcement_save(
    message: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    message = message.strip()
    if len(message) > 1000:
        raise HTTPException(400, "Message must be 1000 characters or fewer")
    prod_set_setting("public_message", message)
    return {"success": True, "message": message}

@app.post("/api/admin/price")
def admin_web_price(
    web_price: int = Form(...),
    voter_search_price: int = Form(1),
    sign_to_server_price: int | None = Form(None),
    auto_birth_price: int | None = Form(None),
    api_price: int | None = Form(None),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    sign_price = web_price if sign_to_server_price is None else sign_to_server_price
    birth_price = int(prod_setting("auto_birth_price", "1")) if auto_birth_price is None else auto_birth_price
    global_api_price = int(prod_setting("api_price", "1")) if api_price is None else api_price
    if min(web_price, voter_search_price, sign_price, birth_price, global_api_price) < 0:
        raise HTTPException(400, "Price cannot be negative")
    prod_set_setting("web_price", str(sign_price))
    prod_set_setting("sign_to_server_price", str(sign_price))
    prod_set_setting("voter_search_price", str(voter_search_price))
    prod_set_setting("auto_birth_price", str(birth_price))
    prod_set_setting("api_price", str(global_api_price))
    return {
        "success": True,
        "web_price": sign_price,
        "sign_to_server_price": sign_price,
        "voter_search_price": voter_search_price,
        "auto_birth_price": birth_price,
        "api_price": global_api_price
    }

@app.get("/api/admin/bkash")
def admin_bkash_status(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    return {
        "success": True,
        "bkash_number": prod_setting("bkash_number", "01925211591") or "01925211591"
    }


@app.post("/api/admin/bkash")
async def admin_bkash_save(
    bkash_number: str = Form(...),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)

    bkash_number = bkash_number.strip()

    if not bkash_number:
        raise HTTPException(400, "bKash number is required")

    if not re.fullmatch(r"01[3-9]\d{8}", bkash_number):
        raise HTTPException(400, "Valid Bangladeshi bKash number দিন (11 digits).")

    prod_set_setting("bkash_number", bkash_number)

    return {
        "success": True,
        "bkash_number": bkash_number
    }


@app.post("/api/admin/background")
async def admin_background(file:UploadFile=File(...), web_session: str | None=Cookie(default=None)):
    require_admin(web_session)
    ext=Path(file.filename or "").suffix.lower()
    allowed={".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp"}
    if ext not in allowed: raise HTTPException(400,"Use JPG, PNG or WEBP")
    content=await file.read()
    if len(content)>8*1024*1024: raise HTTPException(413,"Background must be 8 MB or smaller")
    name=re.sub(r"[^A-Za-z0-9._-]+","_",Path(file.filename).stem).strip("._") or "background"
    name=f"{name}{ext}"
    import base64 as _b64
    set_default_background_db(name,allowed[ext],_b64.b64encode(content).decode())
    sync_default_background_to_local()
    return {"success":True,"selected":name}

@app.post("/api/admin/birth-background")
async def admin_birth_background(file: UploadFile = File(...), web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    ext = Path(file.filename or "").suffix.lower()
    allowed = {".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp"}
    if ext not in allowed:
        raise HTTPException(400, "Use JPG, PNG or WEBP")
    content = await file.read()
    if len(content) > 8 * 1024 * 1024:
        raise HTTPException(413, "Background must be 8 MB or smaller")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(file.filename).stem).strip("._") or "birth_background"
    name = f"{name}{ext}"
    import base64 as _b64
    set_birth_background_db(name, allowed[ext], _b64.b64encode(content).decode())
    return {"success": True, "selected": name}


@app.get("/api/admin/birth-background")
def admin_birth_background_status(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    bg = get_birth_background_db()
    return {"success": True, "background": {
        "name": bg["name"] if bg else "",
        "selected": bool(bg)
    }}


@app.get("/api/admin/background")
def admin_background_status(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    bg=get_default_background_db()
    return {"success":True,"background":{"name":bg["name"] if bg else "", "selected":bool(bg)}}


@app.post("/api/customer/payments")
def customer_submit_payment(
    amount: int = Form(...),
    transaction_id: str = Form(...),
    sender_bkash: str = Form(""),
    note: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    u = require_customer(web_session)

    amount = int(amount)
    transaction_id = transaction_id.strip()
    sender_bkash = sender_bkash.strip()
    note = note.strip()

    if amount <= 0:
        raise HTTPException(400, "Amount must be positive")
    if not transaction_id:
        raise HTTPException(400, "Transaction ID is required")
    if len(transaction_id) > 100:
        raise HTTPException(400, "Transaction ID is too long")
    if len(sender_bkash) > 50:
        raise HTTPException(400, "bKash number is too long")
    if len(note) > 500:
        raise HTTPException(400, "Note is too long")

    # 1 taka = 1 balance credit. Credits are added ONLY after admin approval.
    credits = amount

    with prod_engine.begin() as c:
        if c.execute(
            text("SELECT id FROM web_payments WHERE transaction_id=:t"),
            {"t": transaction_id}
        ).fetchone():
            raise HTTPException(409, "This transaction ID was already submitted")

        pid = _next_id(c, "web_payments")
        c.execute(
            text("""
                INSERT INTO web_payments
                (id,user_id,amount,credits,transaction_id,sender_bkash,status,note,created_at,verified_at)
                VALUES
                (:id,:u,:a,:cr,:t,:sender,'pending',:note,:dt,NULL)
            """),
            {
                "id": pid,
                "u": u["id"],
                "a": amount,
                "cr": credits,
                "t": transaction_id,
                "sender": sender_bkash,
                "note": note,
                "dt": datetime.utcnow().isoformat(),
            }
        )

    return {
        "success": True,
        "status": "pending",
        "message": "Payment request submitted. Admin approval-এর পর Balance যোগ হবে."
    }


@app.get("/api/customer/payments")
def customer_payments(web_session: str | None = Cookie(default=None)):
    u = require_customer(web_session)

    with prod_engine.begin() as c:
        rows = c.execute(
            text("""
                SELECT
                    id, amount, credits, transaction_id, sender_bkash,
                    status, note, created_at, verified_at
                FROM web_payments
                WHERE user_id=:u
                ORDER BY id DESC
                LIMIT 100
            """),
            {"u": u["id"]}
        ).mappings().all()

    return {"success": True, "payments": [dict(r) for r in rows]}


@app.get("/api/admin/payments")
def admin_payments(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)

    with prod_engine.begin() as c:
        rows = c.execute(
            text("""
                SELECT
                    p.id,
                    p.amount,
                    p.credits,
                    p.transaction_id,
                    p.sender_bkash,
                    p.status,
                    p.note,
                    p.created_at,
                    p.verified_at,
                    u.email,
                    COALESCE(u.full_name,'') AS full_name,
                    COALESCE(u.mobile,'') AS mobile
                FROM web_payments p
                JOIN web_users u ON u.id=p.user_id
                ORDER BY
                    CASE WHEN p.status='pending' THEN 0 ELSE 1 END,
                    p.id DESC
                LIMIT 200
            """)
        ).mappings().all()

    return {"success": True, "payments": [dict(r) for r in rows]}


@app.post("/api/admin/payments/{payment_id}/approve")
def admin_approve_payment(
    payment_id: int,
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)

    with prod_engine.begin() as c:
        p = c.execute(
            text("SELECT * FROM web_payments WHERE id=:id"),
            {"id": payment_id}
        ).mappings().first()

        if not p:
            raise HTTPException(404, "Payment request not found")

        if p["status"] != "pending":
            raise HTTPException(400, "This payment request is already processed")

        wallet = c.execute(
            text("SELECT credits FROM web_wallets WHERE user_id=:u"),
            {"u": p["user_id"]}
        ).fetchone()

        current_balance = int(wallet[0]) if wallet else 0
        new_balance = current_balance + int(p["credits"])

        if wallet:
            c.execute(
                text("UPDATE web_wallets SET credits=:c WHERE user_id=:u"),
                {"c": new_balance, "u": p["user_id"]}
            )
        else:
            c.execute(
                text("INSERT INTO web_wallets(user_id,credits) VALUES(:u,:c)"),
                {"u": p["user_id"], "c": new_balance}
            )

        c.execute(
            text("""
                UPDATE web_payments
                SET status='approved',
                    verified_at=:t,
                    note=:note
                WHERE id=:id
            """),
            {
                "t": datetime.utcnow().isoformat(),
                "note": "Approved by admin",
                "id": payment_id
            }
        )

    return {
        "success": True,
        "message": "Payment approved and balance added.",
        "balance": new_balance
    }


@app.post("/api/admin/payments/{payment_id}/reject")
def admin_reject_payment(
    payment_id: int,
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)

    with prod_engine.begin() as c:
        p = c.execute(
            text("SELECT status FROM web_payments WHERE id=:id"),
            {"id": payment_id}
        ).mappings().first()

        if not p:
            raise HTTPException(404, "Payment request not found")

        if p["status"] != "pending":
            raise HTTPException(400, "This payment request is already processed")

        c.execute(
            text("""
                UPDATE web_payments
                SET status='rejected',
                    verified_at=:t,
                    note=:note
                WHERE id=:id
            """),
            {
                "t": datetime.utcnow().isoformat(),
                "note": "Rejected by admin",
                "id": payment_id
            }
        )

    return {"success": True, "message": "Payment request rejected."}


@app.get("/api/customer/status")
def customer_status(web_session: str | None = Cookie(default=None)):
    u = require_customer(web_session)

    # Older accounts may have been created before wallet initialization.
    with prod_engine.begin() as c:
        c.execute(
            text("""
                INSERT INTO web_wallets(user_id, credits)
                VALUES(:u, 0)
                ON CONFLICT (user_id) DO NOTHING
            """),
            {"u": u["id"]}
        )

    return {
        "success": True,
        "balance": prod_balance(u["id"]),
        "price": int(prod_setting("sign_to_server_price", prod_setting("web_price", "1"))),
        "sign_to_server_price": int(prod_setting("sign_to_server_price", prod_setting("web_price", "1"))),
        "auto_birth_price": int(prod_setting("auto_birth_price", "1")),
        "api_price": int(prod_setting("api_price", "1")),
        "voter_search_price": int(prod_setting("voter_search_price", "1")),
        "bkash_number": prod_setting("bkash_number", "01925211591") or "01925211591"
    }
    # ============================================================
# CUSTOMER MANAGEMENT
# ============================================================

@app.get("/api/admin/customers")
def admin_customers(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)

    with prod_engine.begin() as c:
        rows = c.execute(
            text("""
                SELECT
                    u.id,
                    u.email,
                    u.role,
                    u.active,
                    u.created_at,
                    u.full_name,
                    u.mobile,
                    COALESCE(w.credits, 0) AS credits
                FROM web_users u
                LEFT JOIN web_wallets w ON w.user_id = u.id
                WHERE u.role = 'customer'
                ORDER BY u.id DESC
            """)
        ).mappings().all()

    return {
        "success": True,
        "customers": [dict(row) for row in rows]
    }


@app.post("/api/admin/customer/update")
async def admin_update_customer(
    user_id: int = Form(...),
    email: str = Form(...),
    full_name: str = Form(""),
    mobile: str = Form(""),
    role: str = Form("customer"),
    active: int = Form(1),
    new_password: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)

    email = email.strip().lower()
    full_name = full_name.strip()
    mobile = mobile.strip()
    role = role.strip() or "customer"

    if not email:
        raise HTTPException(400, "Email is required")

    if role not in ("customer", "admin"):
        role = "customer"

    active = 1 if int(active) else 0

    with prod_engine.begin() as c:
        existing = c.execute(
            text("""
                SELECT id
                FROM web_users
                WHERE email=:email AND id<>:user_id
            """),
            {
                "email": email,
                "user_id": user_id
            }
        ).mappings().first()

        if existing:
            raise HTTPException(400, "Email already exists")

        # Password দেওয়া থাকলে password update হবে
        if new_password.strip():
            if len(new_password.strip()) < 6:
                raise HTTPException(
                    400,
                    "New password must be at least 6 characters"
                )

            c.execute(
                text("""
                    UPDATE web_users
                    SET
                        email=:email,
                        full_name=:full_name,
                        mobile=:mobile,
                        role=:role,
                        active=:active,
                        password_hash=:password_hash
                    WHERE id=:user_id
                """),
                {
                    "email": email,
                    "full_name": full_name,
                    "mobile": mobile,
                    "role": role,
                    "active": active,
                    "password_hash": _hash_password(new_password.strip()),
                    "user_id": user_id,
                }
            )
        else:
            c.execute(
                text("""
                    UPDATE web_users
                    SET
                        email=:email,
                        full_name=:full_name,
                        mobile=:mobile,
                        role=:role,
                        active=:active
                    WHERE id=:user_id
                """),
                {
                    "email": email,
                    "full_name": full_name,
                    "mobile": mobile,
                    "role": role,
                    "active": active,
                    "user_id": user_id,
                }
            )

    return {
        "success": True,
        "message": "Customer updated successfully"
    }


@app.post("/api/admin/customer/balance")
def admin_adjust_customer_balance(
    user_id: int = Form(...),
    amount: int = Form(...),
    web_session: str | None = Cookie(default=None)
):
    """Admin-only manual balance adjustment. Positive=add, negative=deduct."""
    require_admin(web_session)

    amount = int(amount)
    if amount == 0:
        raise HTTPException(400, "Balance amount cannot be zero")

    with prod_engine.begin() as c:
        user = c.execute(
            text("SELECT id, role FROM web_users WHERE id=:user_id"),
            {"user_id": user_id}
        ).mappings().first()

        if not user or user["role"] != "customer":
            raise HTTPException(404, "Customer not found")

        wallet = c.execute(
            text("SELECT credits FROM web_wallets WHERE user_id=:user_id"),
            {"user_id": user_id}
        ).fetchone()
        current_balance = int(wallet[0]) if wallet else 0
        new_balance = current_balance + amount

        if new_balance < 0:
            raise HTTPException(400, "Balance cannot go below 0")

        if wallet:
            c.execute(
                text("UPDATE web_wallets SET credits=:credits WHERE user_id=:user_id"),
                {"credits": new_balance, "user_id": user_id}
            )
        else:
            c.execute(
                text("INSERT INTO web_wallets(user_id,credits) VALUES(:user_id,:credits)"),
                {"user_id": user_id, "credits": new_balance}
            )

    return {
        "success": True,
        "message": "Balance added successfully." if amount > 0 else "Balance deducted successfully.",
        "balance": new_balance
    }


@app.post("/api/admin/customer/delete")
async def admin_delete_customer(
    user_id: int = Form(...),
    web_session: str | None = Cookie(default=None)
):
    admin = require_admin(web_session)

    if int(user_id) == int(admin["id"]):
        raise HTTPException(400, "You cannot delete your own admin account")

    with prod_engine.begin() as c:
        user = c.execute(
            text("SELECT id FROM web_users WHERE id=:user_id"),
            {"user_id": user_id}
        ).mappings().first()

        if not user:
            raise HTTPException(404, "Customer not found")

        # wallet থাকলে আগে delete
        c.execute(
            text("DELETE FROM web_wallets WHERE user_id=:user_id"),
            {"user_id": user_id}
        )

        c.execute(
            text("DELETE FROM web_users WHERE id=:user_id"),
            {"user_id": user_id}
        )

    return {
        "success": True,
        "message": "Customer deleted successfully"
    }


# ============================================================
# USER PROFILE / PASSWORD
# ============================================================

@app.post("/api/user/profile")
async def update_my_profile(
    full_name: str = Form(""),
    mobile: str = Form(""),
    new_password: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    user = require_customer(web_session)

    full_name = full_name.strip()
    mobile = mobile.strip()
    new_password = new_password.strip()

    with prod_engine.begin() as c:

        if new_password:
            if len(new_password) < 6:
                raise HTTPException(
                    400,
                    "New password must be at least 6 characters"
                )

            c.execute(
                text("""
                    UPDATE web_users
                    SET
                        full_name=:full_name,
                        mobile=:mobile,
                        password_hash=:password_hash
                    WHERE id=:user_id
                """),
                {
                    "full_name": full_name,
                    "mobile": mobile,
                    "password_hash": _hash_password(new_password),
                    "user_id": user["id"],
                }
            )
        else:
            c.execute(
                text("""
                    UPDATE web_users
                    SET
                        full_name=:full_name,
                        mobile=:mobile
                    WHERE id=:user_id
                """),
                {
                    "full_name": full_name,
                    "mobile": mobile,
                    "user_id": user["id"],
                }
            )

    return {
        "success": True,
        "message": "Profile updated successfully"
    }


@app.get("/api/user/profile")
def get_my_profile(
    web_session: str | None = Cookie(default=None)
):
    user = require_customer(web_session)

    with prod_engine.begin() as c:
        row = c.execute(
            text("""
                SELECT
                    id,
                    email,
                    full_name,
                    mobile,
                    role
                FROM web_users
                WHERE id=:user_id
            """),
            {"user_id": user["id"]}
        ).mappings().first()

    if not row:
        raise HTTPException(404, "User not found")

    return {
        "success": True,
        "user": dict(row)
    }
async def _parse_source_upload(file: UploadFile):
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400,"Please upload a PDF")
    content=await file.read()
    if len(content)>15*1024*1024: raise HTTPException(413,"PDF must be 15 MB or smaller")
    fd,temp=tempfile.mkstemp(suffix=".pdf"); os.close(fd)
    try:
        Path(temp).write_bytes(content)
        doc=fitz.open(temp)
        pages=[p.get_text("text") for p in doc]
        page1=pages[0] if pages else ""
        all_text="\n".join(pages)
        doc.close()
        d=parse_text(all_text,address_text=page1)
        d["photo_b64"]=extract_photo(temp)
        d["qr_b64"]=make_qr(d.get("name_en",""),d.get("national_id",""),d.get("dob",""))
        return d
    finally:
        try: os.remove(temp)
        except OSError: pass


def _api_key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def _new_api_key() -> str:
    return "mk_live_" + secrets.token_urlsafe(32)

def _api_client_from_request(api_key: str | None):
    if not api_key:
        raise HTTPException(401, "API key required")
    api_key = api_key.strip()
    if api_key.lower().startswith("bearer "):
        api_key = api_key[7:].strip()
    with prod_engine.begin() as c:
        row = c.execute(text("""
            SELECT c.*, p.name AS plan_name, p.price, p.monthly_limit, p.rate_limit, p.max_file_mb, p.active AS plan_active
            FROM api_clients c JOIN api_plans p ON p.id=c.plan_id
            WHERE c.api_key_hash=:h
        """), {"h": _api_key_hash(api_key)}).mappings().first()
    if not row or not row["active"] or not row["plan_active"]:
        raise HTTPException(401, "Invalid or inactive API key")
    if row["expires_at"]:
        try:
            if datetime.fromisoformat(str(row["expires_at"])) <= datetime.utcnow():
                raise HTTPException(403, "API access has expired")
        except ValueError:
            pass
    return dict(row)

def _api_usage_counts(client_id: int):
    now = datetime.utcnow()
    month_prefix = now.strftime("%Y-%m")
    month_start = month_prefix + "-01T00:00:00"
    minute_start = (now - __import__('datetime').timedelta(minutes=1)).isoformat()
    with prod_engine.begin() as c:
        monthly = c.execute(text("SELECT COUNT(*) FROM api_requests WHERE client_id=:c AND status='success' AND created_at>=:s"), {"c":client_id,"s":month_start}).scalar() or 0
        minute = c.execute(text("SELECT COUNT(*) FROM api_requests WHERE client_id=:c AND created_at>=:s"), {"c":client_id,"s":minute_start}).scalar() or 0
    return int(monthly), int(minute)

def _api_log(client_id: int, request_id: str, status: str, filename: str = "", nid: str = "", person_name: str = "", dob: str = "", processing_ms: int = 0):
    with prod_engine.begin() as c:
        rid = _next_id(c, "api_requests")
        c.execute(text("""
            INSERT INTO api_requests(id,client_id,request_id,status,filename,nid,person_name,dob,processing_ms,created_at)
            VALUES(:id,:c,:r,:s,:f,:n,:pn,:dob,:ms,:t)
        """), {"id":rid,"c":client_id,"r":request_id,"s":status,"f":filename,"n":nid,"pn":person_name,"dob":dob,"ms":processing_ms,"t":datetime.utcnow().isoformat()})

@app.get("/api/admin/api/plans")
def admin_api_plans(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    with prod_engine.begin() as c:
        rows=c.execute(text("SELECT * FROM api_plans ORDER BY id DESC")).mappings().all()
    return {"success":True,"plans":[dict(r) for r in rows]}

@app.post("/api/admin/api/plans/save")
def admin_api_plan_save(
    plan_id: str = Form(""), name: str = Form(...), price: str = Form("0"), monthly_limit: int = Form(1000),
    rate_limit: int = Form(30), max_file_mb: int = Form(15), active: int = Form(1),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    name=name.strip()
    if not name: raise HTTPException(400,"Plan name required")
    if monthly_limit<1 or rate_limit<1 or max_file_mb<1 or max_file_mb>50: raise HTTPException(400,"Invalid plan limits")
    with prod_engine.begin() as c:
        if plan_id:
            c.execute(text("UPDATE api_plans SET name=:n,price=:p,monthly_limit=:m,rate_limit=:r,max_file_mb=:f,active=:a WHERE id=:id"), {"n":name,"p":price.strip(),"m":monthly_limit,"r":rate_limit,"f":max_file_mb,"a":1 if active else 0,"id":int(plan_id)})
            pid=int(plan_id)
        else:
            pid=_next_id(c,"api_plans")
            try:
                c.execute(text("INSERT INTO api_plans(id,name,price,monthly_limit,rate_limit,max_file_mb,active,created_at) VALUES(:id,:n,:p,:m,:r,:f,:a,:t)"), {"id":pid,"n":name,"p":price.strip(),"m":monthly_limit,"r":rate_limit,"f":max_file_mb,"a":1 if active else 0,"t":datetime.utcnow().isoformat()})
            except Exception:
                raise HTTPException(409,"Plan name already exists")
    return {"success":True,"message":"API plan saved","id":pid}

@app.get("/api/admin/api/clients")
def admin_api_clients(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    with prod_engine.begin() as c:
        rows=c.execute(text("""
            SELECT c.id,c.name,c.email,c.website,c.api_key_prefix,c.active,c.expires_at,c.created_at,
                   p.id AS plan_id,p.name AS plan_name,p.price,p.monthly_limit,p.rate_limit,
                   (SELECT COUNT(*) FROM api_requests r WHERE r.client_id=c.id AND r.status='success') AS total_requests,
                   (SELECT COUNT(*) FROM api_requests r WHERE r.client_id=c.id AND r.status='success' AND r.created_at>=:ms) AS month_requests
            FROM api_clients c JOIN api_plans p ON p.id=c.plan_id ORDER BY c.id DESC
        """), {"ms":datetime.utcnow().strftime("%Y-%m")+"-01T00:00:00"}).mappings().all()
    return {"success":True,"clients":[dict(r) for r in rows]}

@app.post("/api/admin/api/clients/create")
def admin_api_client_create(
    name: str = Form(...), email: str = Form(""), website: str = Form(""), plan_id: int = Form(...), expires_at: str = Form(""),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    with prod_engine.begin() as c:
        p=c.execute(text("SELECT id,active FROM api_plans WHERE id=:id"),{"id":plan_id}).mappings().first()
        if not p or not p["active"]: raise HTTPException(400,"Invalid/inactive plan")
        key=_new_api_key(); cid=_next_id(c,"api_clients")
        c.execute(text("""
            INSERT INTO api_clients(id,name,email,website,plan_id,api_key_hash,api_key_prefix,active,expires_at,created_at)
            VALUES(:id,:n,:e,:w,:p,:h,:pref,1,:x,:t)
        """), {"id":cid,"n":name.strip(),"e":email.strip().lower(),"w":website.strip(),"p":plan_id,"h":_api_key_hash(key),"pref":key[:16]+"…","x":expires_at.strip(),"t":datetime.utcnow().isoformat()})
    return {"success":True,"message":"API client created","client_id":cid,"api_key":key}

@app.post("/api/admin/api/clients/{client_id}/status")
def admin_api_client_status(client_id:int, active:int=Form(...), web_session: str | None=Cookie(default=None)):
    require_admin(web_session)
    with prod_engine.begin() as c: c.execute(text("UPDATE api_clients SET active=:a WHERE id=:id"),{"a":1 if active else 0,"id":client_id})
    return {"success":True,"message":"API client status updated"}

@app.post("/api/admin/api/clients/{client_id}/plan")
def admin_api_client_plan(client_id:int, plan_id:int=Form(...), web_session: str | None=Cookie(default=None)):
    require_admin(web_session)
    with prod_engine.begin() as c:
        p=c.execute(text("SELECT id,active FROM api_plans WHERE id=:id"),{"id":plan_id}).mappings().first()
        if not p or not p["active"]: raise HTTPException(400,"Invalid/inactive plan")
        c.execute(text("UPDATE api_clients SET plan_id=:p WHERE id=:id"),{"p":plan_id,"id":client_id})
    return {"success":True,"message":"API client plan updated"}

@app.post("/api/admin/api/clients/{client_id}/regenerate")
def admin_api_client_regenerate(client_id:int, web_session: str | None=Cookie(default=None)):
    require_admin(web_session)
    key=_new_api_key()
    with prod_engine.begin() as c: c.execute(text("UPDATE api_clients SET api_key_hash=:h,api_key_prefix=:p WHERE id=:id"),{"h":_api_key_hash(key),"p":key[:16]+"…","id":client_id})
    return {"success":True,"api_key":key}

@app.get("/api/admin/api/requests")
def admin_api_requests(web_session: str | None = Cookie(default=None), client_id: int = 0, limit: int = 500):
    require_admin(web_session); limit=max(1,min(limit,1000))
    where="" if not client_id else "WHERE r.client_id=:cid"
    params={"limit":limit};
    if client_id: params["cid"]=client_id
    with prod_engine.begin() as c:
        rows=c.execute(text(f"""
            SELECT r.*, c.name AS client_name FROM api_requests r JOIN api_clients c ON c.id=r.client_id
            {where} ORDER BY r.id DESC LIMIT :limit
        """),params).mappings().all()
    return {"success":True,"requests":[dict(r) for r in rows]}

@app.get("/api/v1/status")
def api_status(x_api_key: str | None = Header(default=None, alias="X-API-Key"), authorization: str | None = Header(default=None)):
    client=_api_client_from_request(x_api_key or authorization)
    monthly,minute=_api_usage_counts(client["id"])
    return {"success":True,"client":client["name"],"plan":client["plan_name"],"monthly_limit":client["monthly_limit"],"monthly_used":monthly,"remaining":max(0,client["monthly_limit"]-monthly),"rate_limit_per_minute":client["rate_limit"],"requests_last_minute":minute}

@app.post("/api/v1/generate-pdf")
async def api_generate_pdf(file: UploadFile=File(...), x_api_key: str | None = Header(default=None, alias="X-API-Key"), authorization: str | None = Header(default=None)):
    client=_api_client_from_request(x_api_key or authorization)
    monthly,minute=_api_usage_counts(client["id"])
    if monthly>=client["monthly_limit"]: raise HTTPException(429,"Monthly PDF limit reached")
    if minute>=client["rate_limit"]: raise HTTPException(429,"Rate limit exceeded")
    if not file.filename or not file.filename.lower().endswith(".pdf"): raise HTTPException(400,"Please upload a PDF source file")
    max_bytes=int(client["max_file_mb"])*1024*1024
    content=await file.read()
    if len(content)>max_bytes: raise HTTPException(413,f"Source PDF must be {client['max_file_mb']} MB or smaller")
    request_id="req_"+secrets.token_urlsafe(12)
    started=_time.perf_counter()
    try:
        fd,temp=tempfile.mkstemp(suffix=".pdf"); os.close(fd); Path(temp).write_bytes(content)
        doc=fitz.open(temp); pages=[p.get_text("text") for p in doc]; page1=pages[0] if pages else ""; all_text="\n".join(pages); doc.close()
        d=parse_text(all_text,address_text=page1); d["photo_b64"]=extract_photo(temp); d["qr_b64"]=make_qr(d.get("name_en",""),d.get("national_id",""),d.get("dob",""))
        out=make_pdf(d)
        ms=int((_time.perf_counter()-started)*1000)
        person_name=str(d.get("name_bn") or d.get("name_en") or "").strip(); dob=str(d.get("dob") or "").strip(); nid=str(d.get("national_id") or "").strip()
        _api_log(client["id"],request_id,"success",out.name,nid,person_name,dob,ms)
    except Exception as e:
        ms=int((_time.perf_counter()-started)*1000)
        try: _api_log(client["id"],request_id,"failed",processing_ms=ms)
        except Exception: pass
        raise
    finally:
        try: os.remove(temp)
        except Exception: pass
    return FileResponse(out,media_type="application/pdf",filename=out.name,headers={"X-Request-ID":request_id,"X-API-Client":client["name"]},background=BackgroundTask(lambda p=out:p.unlink(missing_ok=True)))

# ============================================================
# DB Clouds — Voter Search All BD
# ============================================================
def _dbclouds_location_base() -> str:
    """
    Build the administrative-location API base from DBCLOUDS_API_URL.
    Example:
      https://dbclouds.store/api/v1/search-voter
      -> https://dbclouds.store/api
    """
    parts = urlsplit(DBCLOUDS_API_URL)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}/api"


def _dbclouds_public_location_request(path: str, query: dict | None = None):
    """Server-side proxy for DB Clouds administrative location data."""
    base = _dbclouds_location_base()
    if not base:
        raise HTTPException(503, "Location service is not configured")

    url = base.rstrip("/") + "/" + path.lstrip("/")
    if query:
        query = {k: v for k, v in query.items() if v is not None and str(v) != ""}
        if query:
            url += "?" + urlencode(query)

    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "V1-PDF-Generator/1.0",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=DBCLOUDS_API_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", 200)
    except Exception:
        # Keep provider details out of the customer-facing response.
        raise HTTPException(502, "Location data is temporarily unavailable")

    if status < 200 or status >= 300:
        raise HTTPException(502, "Location data is temporarily unavailable")
    try:
        return json.loads(body)
    except Exception:
        raise HTTPException(502, "Location data is temporarily unavailable")


def _location_items(raw, preferred_keys: tuple[str, ...]) -> list:
    """Accept common DB Clouds JSON shapes without exposing provider details."""
    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict):
        for key in preferred_keys + ("data", "results", "records", "items"):
            value = raw.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]

    return []


def _location_name(item) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        for key in (
            "name", "bn_name", "district", "district_name",
            "upazila", "upazila_name", "subdistrict", "subdistrict_name",
        ):
            value = item.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
    return ""


@app.get("/api/customer/voter-locations/districts")
def voter_location_districts(web_session: str | None = Cookie(default=None)):
    require_customer(web_session)
    raw = _dbclouds_public_location_request("districts")
    items = _location_items(raw, ("districts",))
    names = []
    seen = set()
    for item in items:
        name = _location_name(item)
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return {"success": True, "districts": names}


@app.get("/api/customer/voter-locations/upazilas")
def voter_location_upazilas(
    district: str = "",
    web_session: str | None = Cookie(default=None),
):
    require_customer(web_session)
    district = district.strip()
    if not district:
        raise HTTPException(400, "District is required")

    raw = _dbclouds_public_location_request("upazilas/" + quote(district, safe=""))
    items = _location_items(raw, ("upazilas",))
    names = []
    seen = set()
    for item in items:
        name = _location_name(item)
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return {"success": True, "district": district, "upazilas": names}


def _dbclouds_configured() -> bool:
    return bool(DBCLOUDS_API_URL and DBCLOUDS_API_KEY)


def _dbclouds_request(payload: dict):
    if not _dbclouds_configured():
        raise HTTPException(503, "DB Clouds API is not configured. Set DBCLOUDS_API_URL and DBCLOUDS_API_KEY on the server.")
    method = DBCLOUDS_API_METHOD if DBCLOUDS_API_METHOD in ("GET", "POST") else "POST"
    headers = {
        "Accept": "application/json",
        "User-Agent": "V1-PDF-Generator/1.0",
        DBCLOUDS_API_KEY_HEADER: DBCLOUDS_API_KEY,
    }
    try:
        if method == "GET":
            url = DBCLOUDS_API_URL + ("&" if "?" in DBCLOUDS_API_URL else "?") + urlencode(payload)
            req = Request(url, headers=headers, method="GET")
        else:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
            req = Request(DBCLOUDS_API_URL, data=raw, headers=headers, method="POST")
        with urlopen(req, timeout=DBCLOUDS_API_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", 200)
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[-1200:]
        raise HTTPException(502, f"DB Clouds API error ({e.code}): {detail or e.reason}")
    except (URLError, TimeoutError) as e:
        raise HTTPException(502, f"DB Clouds API connection failed: {e}")
    except Exception as e:
        raise HTTPException(502, f"DB Clouds API request failed: {e}")
    if status < 200 or status >= 300:
        raise HTTPException(502, f"DB Clouds API returned HTTP {status}")
    try:
        return json.loads(body)
    except Exception:
        raise HTTPException(502, "DB Clouds API did not return valid JSON")


def _dbclouds_results(raw):
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("data", "results", "voters", "records", "result"):
            value = raw.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]
        # Some APIs return one record directly.
        if any(k in raw for k in ("name", "voter_no", "voter_number", "father_name", "mother_name")):
            return [raw]
    return []


def _normalize_voter_result(item: dict) -> dict:
    def pick(*keys):
        for key in keys:
            v = item.get(key)
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        return ""
    return {
        "name": pick("name", "full_name"),
        "voter_no": pick("voter_no", "voter_number", "voterNo"),
        "father_name": pick("father_name", "father", "fatherName"),
        "mother_name": pick("mother_name", "mother", "motherName"),
        "birth_date": pick("birth_date", "dob", "date_of_birth", "birthDate"),
        "profession": pick("profession", "occupation"),
        "district": pick("district", "zilla"),
        "upazila": pick("subdistrict", "upazila", "sub_district", "subDistrict"),
        "village": pick("village", "gram", "village_name"),
        "post_office": pick("post_office", "postOffice", "post_office_name"),
        "postcode": pick("postcode", "postal_code", "postalCode"),
        "gender": pick("gender", "sex"),
        "address": pick("address", "full_address"),
    }

def _mask_voter_number(value: str) -> str:
    """Hide every voter-number digit in the locked search preview."""
    value = str(value or "").strip()
    return "*" * len(value) if value else ""


def _save_voter_search(user_id: int, query: dict, result: dict) -> int:
    with prod_engine.begin() as c:
        sid = _next_id(c, "voter_searches")
        c.execute(text("""
            INSERT INTO voter_searches(id,user_id,query_json,result_json,unlocked,charged,created_at)
            VALUES(:id,:u,:q,:r,0,0,:t)
        """), {
            "id": sid, "u": user_id,
            "q": json.dumps(query, ensure_ascii=False),
            "r": json.dumps(result, ensure_ascii=False),
            "t": datetime.utcnow().isoformat(),
        })
    return sid


@app.get("/api/customer/voter-search/config")
def voter_search_config(web_session: str | None = Cookie(default=None)):
    require_customer(web_session)
    return {
        "success": True,
        "configured": _dbclouds_configured(),
        "price": int(prod_setting("voter_search_price", "1")),
    }


@app.post("/api/customer/voter-search")
async def voter_search_all_bd(
    district: str = Form(""),
    upazila: str = Form(""),
    dob: str = Form(""),
    name: str = Form(""),
    father_name: str = Form(""),
    mother_name: str = Form(""),
    web_session: str | None = Cookie(default=None),
):
    u = require_customer(web_session)
    district = district.strip(); upazila = upazila.strip(); dob = dob.strip()
    name = name.strip(); father_name = father_name.strip(); mother_name = mother_name.strip()
    if not district or not upazila:
        raise HTTPException(400, "জেলা এবং উপজেলা দিতে হবে")
    if not any((dob, name, father_name, mother_name)):
        raise HTTPException(400, "জন্ম তারিখ, নাম, পিতার নাম বা মাতার নামের অন্তত একটি দিন")
    # DB Clouds test panel expects these exact query parameter names.
    payload = {
        "district": district,
        "upazila": upazila,
        "dob": dob,
        "name": name,
        "father": father_name,
        "mother": mother_name,
    }
    # Do not send empty optional parameters when using the GET API.
    payload = {k: v for k, v in payload.items() if v}
    raw = _dbclouds_request(payload)
    items = _dbclouds_results(raw)
    normalized = [_normalize_voter_result(x) for x in items if isinstance(x, dict)]
    normalized = [x for x in normalized if any(x.values())]
    previews = []
    for result in normalized:
        sid = _save_voter_search(u["id"], payload, result)
        previews.append({
            "result_id": sid,
            # Search preview: name are fully visible.
            "name": result.get("name", ""),

            # Search preview: father/spouse and mother names are fully visible.
            "father_name": result.get("father_name", ""),
            "mother_name": result.get("mother_name", ""),

            # Search preview: voter number is completely masked.
            "voter_no": _mask_voter_number(result.get("voter_no", "")),

            # Location fields remain fully visible.
            "district": result.get("district", "") or district,
            "upazila": result.get("upazila", "") or upazila,
            "village": result.get("village", ""),
            "post_office": result.get("post_office", ""),
            "postcode": result.get("postcode", ""),
            "unlocked": False,
        })
    return {"success": True, "count": len(previews), "results": previews}


@app.post("/api/customer/voter-search/{search_id}/unlock")
def voter_search_unlock(
    search_id: int,
    web_session: str | None = Cookie(default=None),
):
    u = require_customer(web_session)
    with prod_engine.begin() as c:
        row = c.execute(text("SELECT * FROM voter_searches WHERE id=:id AND user_id=:u"), {"id": search_id, "u": u["id"]}).mappings().first()
    if not row:
        raise HTTPException(404, "Search result not found or expired")
    result = json.loads(str(row["result_json"] or "{}"))
    if int(row["unlocked"] or 0):
        return {"success": True, "result_id": search_id, "result": result, "balance": prod_balance(u["id"])}
    price = 0 if u.get("role") == "admin" else int(prod_setting("voter_search_price", "1"))
    new_balance = prod_balance(u["id"]) if price == 0 else prod_charge(u["id"], price)
    try:
        with prod_engine.begin() as c:
            c.execute(text("UPDATE voter_searches SET unlocked=1,charged=:ch WHERE id=:id AND user_id=:u"), {"ch": price, "id": search_id, "u": u["id"]})
    except Exception:
        if price:
            with prod_engine.begin() as c:
                c.execute(text("UPDATE web_wallets SET credits=credits+:a WHERE user_id=:u"), {"a": price, "u": u["id"]})
        raise
    return {"success": True, "result_id": search_id, "result": result, "balance": new_balance, "charged": price}


@app.post("/api/customer/birth-reference")
async def customer_birth_reference(
    birth_reg_no: str = Form(...),
    dob: str = Form(...),
    date_of_registration: str = Form(""),
    date_of_issuance: str = Form(""),
    name_bn: str = Form(""),
    name_en: str = Form(""),
    father: str = Form(""),
    father_en: str = Form(""),
    mother: str = Form(""),
    mother_en: str = Form(""),
    nationality: str = Form("Bangladeshi"),
    father_nationality_bn: str = Form(""),
    father_nationality_en: str = Form(""),
    mother_nationality_bn: str = Form(""),
    mother_nationality_en: str = Form(""),
    dob_words: str = Form(""),
    sex: str = Form(""),
    birth_place: str = Form(""),
    birth_place_bn: str = Form(""),
    birth_place_en: str = Form(""),
    union_en: str = Form(""),
    upazila_district_en: str = Form(""),
    permanent_bn: str = Form(""),
    permanent_en: str = Form(""),
    web_session: str | None = Cookie(default=None),
):
    u=require_customer(web_session)
    if not re.fullmatch(r"\d{17}", birth_reg_no.strip()):
        raise HTTPException(400,"Birth Registration Number must contain exactly 17 digits")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dob.strip()):
        raise HTTPException(400,"Date of Birth must be YYYY-MM-DD")
    price=0 if u.get("role")=="admin" else int(prod_setting("auto_birth_price", "1"))
    new_balance=prod_balance(u["id"]) if u.get("role")=="admin" else prod_charge(u["id"],price)
    # Customers never upload a background. The admin-selected Auto Birth
    # background is used until the admin changes it. If an older deployment
    # does not yet have the optional background table, PDF generation should
    # still work without a background.
    bg_b64 = ""
    bg_mime = "image/jpeg"
    try:
        saved_bg = get_birth_background_db()
    except Exception as bg_err:
        print("AUTO BIRTH BACKGROUND LOAD ERROR:", repr(bg_err))
        saved_bg = None
    if saved_bg:
        bg_b64 = saved_bg.get("data", "") or ""
        bg_mime = saved_bg.get("mime", "image/jpeg") or "image/jpeg"
    if not dob_words.strip():
        dob_words = birth_dob_in_words(dob.strip())
    d=locals().copy()
    d.pop("web_session",None); d.pop("u",None); d.pop("price",None); d.pop("new_balance",None); d.pop("bg_b64",None); d.pop("bg_mime",None)
    try:
        out = make_birth_reference_pdf(d, bg_b64, bg_mime)
        save_generation(
            u["id"], birth_reg_no.strip(), out.name, price,
            person_name=name_bn.strip() or name_en.strip(),
            dob=dob.strip(), channel="birth-reference"
        )
    except HTTPException:
        if price:
            with prod_engine.begin() as c:
                c.execute(
                    text("UPDATE web_wallets SET credits=credits+:a WHERE user_id=:u"),
                    {"a": price, "u": u["id"]}
                )
        raise
    except Exception as e:
        print("AUTO BIRTH PDF ERROR:", repr(e))
        if price:
            with prod_engine.begin() as c:
                c.execute(
                    text("UPDATE web_wallets SET credits=credits+:a WHERE user_id=:u"),
                    {"a": price, "u": u["id"]}
                )
        raise HTTPException(500, f"Auto Birth PDF generation failed: {str(e)[-600:]}")
    return FileResponse(out,media_type="application/pdf",filename=out.name,headers={"Content-Disposition":f'attachment; filename="{out.name}"',"X-PDF-Charged":str(price),"X-PDF-Balance":str(new_balance)},background=BackgroundTask(lambda p=out:p.unlink(missing_ok=True)))

@app.post("/api/customer/parse")
async def customer_parse(file:UploadFile=File(...), web_session: str | None = Cookie(default=None)):
    require_customer(web_session)
    d=await _parse_source_upload(file)
    return {"success":True,"data":d}

@app.post("/api/customer/generate")
async def customer_generate(
    data_json: str = Form(...),
    web_session: str | None = Cookie(default=None)
):
    u = require_customer(web_session)
    try:
        d = json.loads(data_json)
    except Exception:
        raise HTTPException(400, "Invalid data JSON")

    # The background is already synced at startup or after an admin upload.
    # Keeping this out of the hot path removes an unnecessary DB read + image
    # decode/write from every PDF generation request.
    # Admin can generate PDFs directly without any balance/credit charge.
    # Customers continue to use the normal configured PDF price.
    price = 0 if u.get("role") == "admin" else int(prod_setting("sign_to_server_price", prod_setting("web_price", "1")))
    nid = str(d.get("national_id", "")).strip()
    if not nid:
        raise HTTPException(400, "NID number is required")

    new_balance = prod_balance(u["id"]) if u.get("role") == "admin" else prod_charge(u["id"], price)
    d["qr_b64"] = make_qr(
        d.get("name_en", ""),
        d.get("national_id", ""),
        d.get("dob", "")
    )

    try:
        out = make_pdf(d)
        person_name = str(d.get("name_bn") or d.get("name_en") or "").strip()
        dob = str(d.get("dob") or "").strip()
        save_generation(
            u["id"], nid, out.name, price,
            person_name=person_name, dob=dob,
            channel="admin" if u.get("role") == "admin" else "web"
        )
    except Exception:
        with prod_engine.begin() as c:
            c.execute(
                text("UPDATE web_wallets SET credits=credits+:a WHERE user_id=:u"),
                {"a": price, "u": u["id"]}
            )
        raise

    return FileResponse(
        out,
        media_type="application/pdf",
        filename=out.name,
        headers={
            "Content-Disposition": f'attachment; filename="{out.name}"',
            "X-PDF-Charged": str(price),
            "X-PDF-Balance": str(new_balance),
        },
        background=BackgroundTask(lambda p=out: p.unlink(missing_ok=True)),
    )


@app.get("/api/admin/generation-history")
def admin_generation_history(
    web_session: str | None = Cookie(default=None),
    limit: int = 500,
):
    """Admin-only PDF make history. Date filtering is handled in the UI using Dhaka time."""
    require_admin(web_session)
    limit = max(1, min(int(limit or 500), 1000))
    with prod_engine.begin() as c:
        rows = c.execute(text("""
            SELECT
                g.id,
                CASE WHEN u.role='admin' THEN 'Admin' ELSE COALESCE(NULLIF(u.email,''),'Customer') END AS username,
                g.nid,
                COALESCE(g.person_name,'') AS person_name,
                COALESCE(g.dob,'') AS dob,
                g.created_at,
                g.channel
            FROM web_generations g
            JOIN web_users u ON u.id=g.user_id
            ORDER BY g.id DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()
    return {"success": True, "history": [dict(r) for r in rows]}


@app.get("/api/customer/history")
def customer_history(web_session: str | None = Cookie(default=None)):
    u = require_customer(web_session)
    with prod_engine.begin() as c:
        rows = c.execute(text("""
            SELECT id,nid,filename,charged,created_at
            FROM web_generations
            WHERE user_id=:u
            ORDER BY id DESC
            LIMIT 5
        """), {"u": u["id"]}).mappings().all()
    return {"success": True, "history": [dict(r) for r in rows]}


@app.get("/",response_class=HTMLResponse)
def home(): return (STATIC/"index.html").read_text(encoding="utf-8")

@app.get("/download/{filename}")
def download(filename:str):
    p=GENERATED/filename
    if not p.exists(): raise HTTPException(404,"File not found")
    return FileResponse(p, media_type="application/pdf", filename=p.name)

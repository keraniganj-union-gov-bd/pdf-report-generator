from pathlib import Path
import base64, html, io, json, os, re, sqlite3, tempfile, uuid
from datetime import datetime

import fitz
import qrcode
from PIL import Image
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import subprocess, time, shutil, platform, secrets, hashlib, hmac
from typing import Optional

from fastapi import Cookie, Depends
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

    if PROD_DB_URL.startswith("postgresql://"):
        PROD_DB_URL = "cockroachdb+psycopg2://" + PROD_DB_URL[len("postgresql://"):]

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
                created_at VARCHAR(40) NOT NULL
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
        # Backward-compatible migration for older local web databases.
        try:
            c.execute(text("ALTER TABLE web_generations ADD COLUMN pdf_data TEXT"))
        except Exception:
            pass

        # Seed IDs manually so SQLite and Cockroach both work without
        # database-specific autoincrement syntax.
        admin = c.execute(text("SELECT id FROM web_users WHERE email=:e"), {"e": ADMIN_EMAIL}).fetchone()
        if not admin:
            c.execute(text(
                "INSERT INTO web_users(id,email,password_hash,role,active,created_at) "
                "VALUES(:id,:e,:p,'admin',1,:t)"
            ), {"id": 1, "e": ADMIN_EMAIL, "p": _hash_password(ADMIN_PASSWORD), "t": datetime.utcnow().isoformat()})
            c.execute(text("INSERT INTO web_wallets(user_id,credits) VALUES(1,0)"))
        for key, value in [("web_price","1"),("api_price","1")]:
            c.execute(text(
                "INSERT INTO web_settings(key,value) VALUES(:k,:v) "
                "ON CONFLICT(key) DO NOTHING"
            ), {"k": key, "v": value})

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

def save_generation(user_id: int, nid: str, filename: str, charged: int, pdf_data_b64: str = ""):
    with prod_engine.begin() as c:
        gid = _next_id(c, "web_generations")
        c.execute(text(
            "INSERT INTO web_generations(id,user_id,nid,filename,channel,charged,pdf_data,created_at) "
            "VALUES(:id,:u,:n,:f,'web',:ch,:pdf,:t)"
        ), {"id":gid,"u":user_id,"n":nid,"f":filename,"ch":charged,"pdf":pdf_data_b64,"t":datetime.utcnow().isoformat()})


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

def selected_background_data_url():
    name = setting_str("background_image", "").strip()
    if not name:
        return ""
    # Prevent path traversal and only allow files inside BACKGROUNDS.
    safe = Path(name).name
    p = BACKGROUNDS / safe
    if not p.exists() or not p.is_file():
        return ""
    ext = p.suffix.lower()
    mime = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
    }.get(ext)
    if not mime:
        return ""
    return f"data:{mime};base64,{base64.b64encode(p.read_bytes()).decode()}"

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
* {{ box-sizing:border-box; }}
body {{ font-family:Bangla,sans-serif; color:#111; font-size:13px; font-weight:400; line-height:1.24; -webkit-font-smoothing:antialiased; margin:0; padding:2.5in 0.8in 1.2in 2.5in; }}
.header, .notice, .section, table, .address, .footer {{ background:rgba(255,255,255,.96); border:0 !important; }}
.page-bg {{ position:fixed; left:0; top:0; width:210mm; height:297mm; object-fit:fill; opacity:1; z-index:0; pointer-events:none; }}
.report-content {{ position:relative; z-index:1; }}
.header {{ padding:7px 10px; text-align:center; margin-bottom:7px; }}
h1 {{ margin:0; font-size:19px; }}
.sub {{ font-size:8px; font-weight:bold; margin-top:2px; }}
.notice {{ margin:5px 0 8px; padding:4px 7px; text-align:center; font-size:8px; font-weight:bold; }}
.top {{ display:block; position:relative; }}
.media {{ position:fixed; left:0; top:92mm; width:71.12mm; display:flex; flex-direction:column; align-items:center; z-index:2; }}
.photo-name {{ margin-top:2mm; font-family:"Segoe UI","Arial",sans-serif; font-size:14px; font-weight:700; text-align:center; max-width:60mm; word-break:break-word; letter-spacing:.1px; }}
.photo {{ width:30.48mm; height:auto; max-height:none; object-fit:contain; border:0.6pt solid #777; border-radius:2.2mm; }}
.empty {{ display:flex; align-items:center; justify-content:center; }}
.qr {{ width:25.4mm; height:25.4mm; margin-top:4mm; }}
.section {{ margin-top:3px; margin-bottom:1px; background:#c2e4eb; border:0 !important; padding:4px 8px; font-size:17px; font-weight:700; line-height:1.18; }}
table {{ width:100%; border-collapse:collapse; }}
td {{ border:0.45pt solid #dedede !important; padding:3px 5px; vertical-align:top; background:#fff; }}
.label {{ width:35.5%; font-weight:400; font-size:13px; line-height:1.32; -webkit-font-smoothing:antialiased; background:#f7f7f7; border:0.45pt solid #dedede !important; }}
.value {{ background:#fff; border:0.45pt solid #dedede !important; font-weight:400; }}
.address {{ border:0.45pt solid #e6e6e6 !important; padding:4px 6px; line-height:1.40; font-weight:400; min-height:0; margin-bottom:3px; overflow-wrap:anywhere; word-break:break-word; background:#fff; }}
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

    html_path.write_text(html_doc, encoding="utf-8")
    browser = _find_browser()
    if not browser:
        raise HTTPException(500, "Chrome or Microsoft Edge was not found.")

    cmd = [
        browser, "--headless=new", "--disable-gpu", "--no-sandbox",
        "--disable-extensions", "--no-pdf-header-footer",
        "--run-all-compositor-stages-before-draw", "--virtual-time-budget=1500",
        f"--print-to-pdf={str(out)}", html_path.resolve().as_uri()
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode != 0 or not out.exists() or out.stat().st_size < 1000:
            cmd[1] = "--headless"
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode != 0 or not out.exists() or out.stat().st_size < 1000:
            raise HTTPException(500, (result.stderr or result.stdout or "PDF generation failed")[-1200:])
        return out
    finally:
        try: html_path.unlink(missing_ok=True)
        except Exception: pass


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

@app.get("/api/auth/me")
def web_me(web_session: str | None = Cookie(default=None)):
    u = current_user(web_session)
    return {"success":True, "user":{"id":u["id"],"email":u["email"],"role":u["role"]}, "balance":prod_balance(u["id"])}

@app.post("/api/admin/customers")
def admin_create_customer(
    email: str = Form(...), password: str = Form(...), credits: int = Form(0),
    web_session: str | None = Cookie(default=None)
):
    require_admin(web_session)
    email=email.strip().lower()
    if len(password) < 8: raise HTTPException(400, "Password must be at least 8 characters")
    if credits < 0: raise HTTPException(400, "Credits cannot be negative")
    with prod_engine.begin() as c:
        if c.execute(text("SELECT id FROM web_users WHERE email=:e"), {"e":email}).fetchone():
            raise HTTPException(409, "Customer already exists")
        uid=_next_id(c,"web_users")
        c.execute(text(
            "INSERT INTO web_users(id,email,password_hash,role,active,created_at) "
            "VALUES(:id,:e,:p,'customer',1,:t)"
        ), {"id":uid,"e":email,"p":_hash_password(password),"t":datetime.utcnow().isoformat()})
        c.execute(text("INSERT INTO web_wallets(user_id,credits) VALUES(:u,:c)"), {"u":uid,"c":credits})
    return {"success":True,"id":uid,"email":email,"credits":credits}

@app.get("/api/admin/customers")
def admin_customers(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    with prod_engine.begin() as c:
        rows=c.execute(text("""
            SELECT u.id,u.email,u.active,COALESCE(w.credits,0) credits,u.created_at
            FROM web_users u LEFT JOIN web_wallets w ON w.user_id=u.id
            WHERE u.role='customer' ORDER BY u.id DESC
        """)).mappings().all()
    return {"success":True,"customers":[dict(r) for r in rows]}

@app.post("/api/admin/customers/{user_id}/credit")
def admin_credit_customer(
    user_id:int, amount:int=Form(...), web_session: str | None=Cookie(default=None)
):
    require_admin(web_session)
    if amount == 0: raise HTTPException(400, "Amount cannot be zero")
    with prod_engine.begin() as c:
        r=c.execute(text("SELECT credits FROM web_wallets WHERE user_id=:u"),{"u":user_id}).fetchone()
        if not r: raise HTTPException(404,"Customer wallet not found")
        new=int(r[0])+amount
        if new < 0: raise HTTPException(400,"Balance cannot be negative")
        c.execute(text("UPDATE web_wallets SET credits=:c WHERE user_id=:u"),{"c":new,"u":user_id})
    return {"success":True,"balance":new}

@app.post("/api/admin/price")
def admin_web_price(web_price:int=Form(...), web_session: str | None=Cookie(default=None)):
    require_admin(web_session)
    if web_price < 0: raise HTTPException(400,"Price cannot be negative")
    prod_set_setting("web_price",str(web_price))
    return {"success":True,"web_price":web_price}

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

@app.get("/api/admin/background")
def admin_background_status(web_session: str | None = Cookie(default=None)):
    require_admin(web_session)
    bg=get_default_background_db()
    return {"success":True,"background":{"name":bg["name"] if bg else "", "selected":bool(bg)}}

@app.get("/api/customer/status")
def customer_status(web_session: str | None = Cookie(default=None)):
    u=require_customer(web_session)
    return {"success":True,"balance":prod_balance(u["id"]),"price":int(prod_setting("web_price","1"))}

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

@app.post("/api/customer/parse")
async def customer_parse(file:UploadFile=File(...), web_session: str | None = Cookie(default=None)):
    require_customer(web_session)
    d=await _parse_source_upload(file)
    return {"success":True,"data":d}

@app.post("/api/customer/generate")
async def customer_generate(
    data_json:str=Form(...), web_session: str | None = Cookie(default=None)
):
    u=require_customer(web_session)
    try: d=json.loads(data_json)
    except Exception: raise HTTPException(400,"Invalid data JSON")
    sync_default_background_to_local()
    price=int(prod_setting("web_price","1"))
    # Charge only after validation and before final generation.
    nid=str(d.get("national_id","")).strip()
    if not nid: raise HTTPException(400,"NID number is required")
    new_balance=prod_charge(u["id"],price)
    d["qr_b64"]=make_qr(d.get("name_en",""),d.get("national_id",""),d.get("dob",""))
    try:
        out=make_pdf(d)
    except Exception:
        # Refund if rendering fails.
        with prod_engine.begin() as c:
            c.execute(text("UPDATE web_wallets SET credits=credits+:a WHERE user_id=:u"),{"a":price,"u":u["id"]})
        raise
    save_generation(u["id"],nid,out.name,price,base64.b64encode(out.read_bytes()).decode())
    return {"success":True,"charged":price,"balance":new_balance,"download":f"/download/{out.name}"}

@app.get("/api/customer/history/{generation_id}/download")
def customer_history_download(generation_id:int, web_session: str | None = Cookie(default=None)):
    u=require_customer(web_session)
    with prod_engine.begin() as c:
        r=c.execute(text(
            "SELECT filename,pdf_data FROM web_generations WHERE id=:id AND user_id=:u"
        ),{"id":generation_id,"u":u["id"]}).mappings().first()
    if not r or not r["pdf_data"]:
        raise HTTPException(404,"Stored PDF not found")
    data=base64.b64decode(r["pdf_data"])
    temp=GENERATED / f"history_{generation_id}_{Path(r['filename']).name}"
    temp.write_bytes(data)
    return FileResponse(temp,media_type="application/pdf",filename=Path(r["filename"]).name)

@app.get("/api/customer/history")
def customer_history(web_session: str | None = Cookie(default=None)):
    u=require_customer(web_session)
    with prod_engine.begin() as c:
        rows=c.execute(text("""
            SELECT id,nid,filename,charged,created_at
            FROM web_generations WHERE user_id=:u ORDER BY id DESC
            LIMIT 100
        """),{"u":u["id"]}).mappings().all()
    return {"success":True,"history":[dict(r) for r in rows]}

@app.get("/",response_class=HTMLResponse)
def home(): return (STATIC/"index.html").read_text(encoding="utf-8")

@app.get("/download/{filename}")
def download(filename:str):
    p=GENERATED/filename
    if not p.exists(): raise HTTPException(404,"File not found")
    return FileResponse(p, media_type="application/pdf", filename=p.name)

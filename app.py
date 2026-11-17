from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

ROOT = Path(__file__).resolve().parent
DATABASE_URL = (os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or os.getenv("POSTGRES_PRISMA_URL") or "").strip()
LOCAL_DB = os.getenv("DATABASE_PATH", str(ROOT / "english10-local.db"))
IS_VERCEL = os.getenv("VERCEL", "").lower() == "1"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
_schema_ready = False
_schema_error: str | None = None
_schema_lock = threading.Lock()


def _clean(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.strftime("%Y-%m-%d %H:%M:%S") if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def respond(data: dict, status: int = 200, session_token: str | None = None, clear_session: bool = False):
    response = jsonify(_clean(data))
    response.status_code = status
    secure_cookie = request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
    if session_token is not None:
        response.set_cookie(
            "session", session_token, max_age=14 * 86400, path="/",
            httponly=True, secure=secure_cookie, samesite="Lax",
        )
    elif clear_session:
        response.delete_cookie("session", path="/", httponly=True, secure=secure_cookie, samesite="Lax")
    return response


def hash_pw(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000).hex()


def check_pw(password: str, stored: str | None) -> bool:
    try:
        if not stored:
            return False
        salt_hex, expected = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


@contextmanager
def connection():
    if DATABASE_URL:
        import psycopg
        from psycopg.rows import dict_row

        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        if IS_VERCEL:
            raise RuntimeError("Chưa cấu hình DATABASE_URL. Hãy kết nối PostgreSQL trong Vercel Storage.")
        conn = sqlite3.connect(LOCAL_DB, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def execute(conn, sql: str, params=()):
    if DATABASE_URL:
        sql = sql.replace("?", "%s")
    return conn.execute(sql, params)


def one(conn, sql: str, params=()):
    row = execute(conn, sql, params).fetchone()
    return _clean(dict(row)) if row is not None else None


def all_rows(conn, sql: str, params=()):
    return [_clean(dict(row)) for row in execute(conn, sql, params).fetchall()]


def _seed_curriculum(conn):
    units = [
        ("u1", "Unit 1: Family life", "Family life"),
        ("u2", "Unit 2: Humans and the environment", "Humans and the environment"),
        ("u3", "Unit 3: Music", "Music"),
        ("u4", "Unit 4: For a better community", "For a better community"),
        ("u5", "Unit 5: Inventions", "Inventions"),
        ("u6", "Unit 6: Gender equality", "Gender equality"),
        ("u7", "Unit 7: Viet Nam and international organisations", "Viet Nam and international organisations"),
        ("u8", "Unit 8: New ways to learn", "New ways to learn"),
        ("u9", "Unit 9: Protecting the environment", "Protecting the environment"),
        ("u10", "Unit 10: Ecotourism", "Ecotourism"),
    ]
    activities = {
        "u1": ("household chores", "Who usually does the cooking in your family?", "I help my family with household chores."),
        "u2": ("green lifestyle", "What can students do to protect the environment?", "We should reduce plastic waste and save energy."),
        "u3": ("music", "What kind of music do you enjoy?", "Music helps me relax and connect with other people."),
        "u4": ("volunteering", "Why do people volunteer?", "Volunteers help people in need and improve their community."),
        "u5": ("smartphone", "How does a smartphone help students learn?", "It gives students quick access to useful information."),
        "u6": ("equal opportunity", "What does gender equality mean?", "Everyone should have equal opportunities at school and work."),
        "u7": ("international cooperation", "What does Viet Nam contribute to international cooperation?", "Viet Nam works with other countries to build peace and development."),
        "u8": ("online learning", "What is one advantage of online learning?", "Learners can study flexibly and review lessons at their own pace."),
        "u9": ("biodiversity", "Why should we protect biodiversity?", "Biodiversity keeps ecosystems healthy and supports human life."),
        "u10": ("responsible tourism", "How can tourists protect a destination?", "Tourists should respect local people, wildlife and the environment."),
    }
    module_specs = [("Vocabulary", "vocabulary"), ("Reading", "reading"), ("Listening", "listening"), ("Speaking", "speaking"), ("Writing", "writing")]
    for ui, (uid, title, topic) in enumerate(units, 1):
        content = json.dumps({"source": "KNTT Global Success 10", "status": "adapted_practice", "topic": topic}, ensure_ascii=False)
        execute(conn, "INSERT INTO lessons(id,title,unit,content_json) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING", (uid, title, f"Unit {ui}", content))
        key, question, model = activities[uid]
        for mi, (skill, kind) in enumerate(module_specs, 1):
            mid = f"{uid}-m{mi}"
            execute(conn, "INSERT INTO modules(id,lesson_id,title,skill,minutes,sort_order) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING", (mid, uid, skill, skill.lower(), 5, mi))
            prompts = [f'Choose the best meaning of “{key}”.', question, f'Complete a short {skill.lower()} task about {key}.']
            answers = [key, topic, model]
            for ii in range(3):
                iid = f"{mid}-i{ii + 1}"
                item_type = "mcq" if ii == 0 else ("audio" if kind == "listening" else ("recording" if kind == "speaking" else ("text" if kind == "writing" else "short_answer")))
                options = [key, "an unrelated idea", "a difficult problem", "a school subject"] if ii == 0 else []
                rubric = {"accuracy": 40, "vocabulary": 20, "grammar": 20, "communication": 20} if kind in ("speaking", "writing") else {}
                execute(conn, """INSERT INTO items(id,module_id,item_type,prompt,answer,options_json,media_url,rubric_json,sort_order)
                    VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
                    (iid, mid, item_type, prompts[ii], answers[ii], json.dumps(options, ensure_ascii=False), None, json.dumps(rubric, ensure_ascii=False), ii + 1))


def initialize_database():
    global _schema_ready, _schema_error
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        try:
            with connection() as conn:
                if DATABASE_URL:
                    schema = [
                        "CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT,role TEXT NOT NULL DEFAULT 'student',google_sub TEXT UNIQUE,verified INTEGER NOT NULL DEFAULT 0,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
                        "CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires BIGINT NOT NULL)",
                        "CREATE TABLE IF NOT EXISTS reset_tokens(token TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires BIGINT NOT NULL,used INTEGER DEFAULT 0)",
                        "CREATE TABLE IF NOT EXISTS attempts(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,lesson_id TEXT NOT NULL,score DOUBLE PRECISION NOT NULL,duration INTEGER DEFAULT 0,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
                        "CREATE TABLE IF NOT EXISTS lessons(id TEXT PRIMARY KEY,title TEXT NOT NULL,unit TEXT NOT NULL,content_json TEXT NOT NULL)",
                        "CREATE TABLE IF NOT EXISTS modules(id TEXT PRIMARY KEY,lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,title TEXT NOT NULL,skill TEXT NOT NULL,minutes INTEGER DEFAULT 5,sort_order INTEGER DEFAULT 0)",
                        "CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY,module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,item_type TEXT NOT NULL,prompt TEXT NOT NULL,answer TEXT,options_json TEXT,media_url TEXT,rubric_json TEXT,sort_order INTEGER DEFAULT 0)",
                        "CREATE TABLE IF NOT EXISTS progress(user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,completed INTEGER DEFAULT 0,best_score DOUBLE PRECISION DEFAULT 0,seconds INTEGER DEFAULT 0,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(user_id,lesson_id))",
                        "CREATE TABLE IF NOT EXISTS support_messages(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Mới',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
                    ]
                    for statement in schema:
                        conn.execute(statement)
                else:
                    conn.executescript("""
                    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT,role TEXT NOT NULL DEFAULT 'student',google_sub TEXT UNIQUE,verified INTEGER NOT NULL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
                    CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
                    CREATE TABLE IF NOT EXISTS reset_tokens(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL,used INTEGER DEFAULT 0);
                    CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,lesson_id TEXT NOT NULL,score REAL NOT NULL,duration INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
                    CREATE TABLE IF NOT EXISTS lessons(id TEXT PRIMARY KEY,title TEXT NOT NULL,unit TEXT NOT NULL,content_json TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS modules(id TEXT PRIMARY KEY,lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,title TEXT NOT NULL,skill TEXT NOT NULL,minutes INTEGER DEFAULT 5,sort_order INTEGER DEFAULT 0);
                    CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY,module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,item_type TEXT NOT NULL,prompt TEXT NOT NULL,answer TEXT,options_json TEXT,media_url TEXT,rubric_json TEXT,sort_order INTEGER DEFAULT 0);
                    CREATE TABLE IF NOT EXISTS progress(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,completed INTEGER DEFAULT 0,best_score REAL DEFAULT 0,seconds INTEGER DEFAULT 0,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(user_id,lesson_id));
                    CREATE TABLE IF NOT EXISTS support_messages(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Mới',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
                    """)
                admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
                admin_password = os.getenv("ADMIN_PASSWORD", "")
                if admin_email and "@" in admin_email and len(admin_password) >= 12:
                    execute(conn, """INSERT INTO users(email,name,password_hash,role,verified) VALUES(?,?,?,?,1)
                        ON CONFLICT(email) DO UPDATE SET role='admin'""",
                        (admin_email, "Quản trị viên", hash_pw(admin_password), "admin"))
                _seed_curriculum(conn)
            _schema_ready = True
            _schema_error = None
        except Exception as exc:
            _schema_error = str(exc)
            raise


def get_user():
    token = request.cookies.get("session", "").strip()
    if not token:
        return None
    with connection() as conn:
        return one(conn, """SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token=? AND s.expires>?""", (token, int(time.time())))


def require_admin():
    current = get_user()
    return current if current and current.get("role") == "admin" else None


@app.before_request
def prepare_database():
    if request.path.startswith("/api/"):
        try:
            initialize_database()
        except Exception as exc:
            # Do not expose connection strings, passwords, or driver details to visitors.
            app.logger.error("G-STUDY database initialization failed: %s", exc)
            if IS_VERCEL and not DATABASE_URL:
                return respond({"error": "Chưa kết nối PostgreSQL. Hãy thêm DATABASE_URL trong Vercel Storage."}, 503)
            return respond({"error": "Không thể kết nối cơ sở dữ liệu. Kiểm tra DATABASE_URL trong Vercel."}, 503)


@app.get("/")
@app.get("/index.html")
def index():
    return send_file(ROOT / "index.html")


@app.get("/api/me")
def api_me():
    current = get_user()
    if not current:
        return respond({"user": None})
    safe = {k: current[k] for k in ("id", "email", "name", "role", "verified", "created_at")}
    return respond({"user": safe})


@app.get("/api/lessons")
def api_lessons():
    with connection() as conn:
        return respond({"lessons": all_rows(conn, "SELECT id,title,unit FROM lessons ORDER BY unit,title")})


@app.get("/api/lesson/<path:lesson_id>")
def api_lesson(lesson_id):
    with connection() as conn:
        lesson = one(conn, "SELECT id,title,unit,content_json FROM lessons WHERE id=?", (lesson_id,))
        if not lesson:
            return respond({"error": "lesson_not_found"}, 404)
        modules = all_rows(conn, "SELECT id,title,skill,minutes,sort_order FROM modules WHERE lesson_id=? ORDER BY sort_order", (lesson_id,))
        for module in modules:
            module["items"] = all_rows(conn, "SELECT id,item_type,prompt,answer,options_json,media_url,rubric_json FROM items WHERE module_id=? ORDER BY sort_order", (module["id"],))
        return respond({"lesson": lesson, "modules": modules})


@app.get("/api/progress")
def api_progress():
    current = get_user()
    if not current:
        return respond({"error": "unauthorized"}, 401)
    with connection() as conn:
        rows = all_rows(conn, """SELECT p.*,l.title,l.unit FROM progress p JOIN lessons l ON l.id=p.lesson_id
            WHERE p.user_id=? ORDER BY p.updated_at DESC""", (current["id"],))
        if DATABASE_URL:
            agg = one(conn, """SELECT COUNT(*) AS attempts,COALESCE(AVG(score),0) AS average,
                COALESCE(SUM(duration),0) AS seconds,
                COUNT(DISTINCT (created_at AT TIME ZONE 'Asia/Ho_Chi_Minh')::date) AS active_days
                FROM attempts WHERE user_id=?""", (current["id"],))
            today = one(conn, """SELECT COUNT(*) AS attempts,COALESCE(AVG(score),0) AS average,COALESCE(SUM(duration),0) AS seconds
                FROM attempts WHERE user_id=? AND (created_at AT TIME ZONE 'Asia/Ho_Chi_Minh')::date=(NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')::date""", (current["id"],))
            yesterday = one(conn, """SELECT COUNT(*) AS attempts,COALESCE(AVG(score),0) AS average,COALESCE(SUM(duration),0) AS seconds
                FROM attempts WHERE user_id=? AND (created_at AT TIME ZONE 'Asia/Ho_Chi_Minh')::date=((NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')::date - 1)""", (current["id"],))
            week = one(conn, "SELECT COALESCE(SUM(duration),0) AS seconds FROM attempts WHERE user_id=? AND created_at >= NOW() - INTERVAL '7 days'", (current["id"],))
        else:
            agg = one(conn, "SELECT COUNT(*) attempts,COALESCE(AVG(score),0) average,COALESCE(SUM(duration),0) seconds,COUNT(DISTINCT date(created_at)) active_days FROM attempts WHERE user_id=?", (current["id"],))
            today = one(conn, "SELECT COUNT(*) attempts,COALESCE(AVG(score),0) average,COALESCE(SUM(duration),0) seconds FROM attempts WHERE user_id=? AND created_at >= datetime('now','+7 hours','start of day','-7 hours')", (current["id"],))
            yesterday = one(conn, "SELECT COUNT(*) attempts,COALESCE(AVG(score),0) average,COALESCE(SUM(duration),0) seconds FROM attempts WHERE user_id=? AND created_at >= datetime('now','+7 hours','start of day','-1 day','-7 hours') AND created_at < datetime('now','+7 hours','start of day','-7 hours')", (current["id"],))
            week = one(conn, "SELECT COALESCE(SUM(duration),0) seconds FROM attempts WHERE user_id=? AND created_at >= datetime('now','-7 day')", (current["id"],))
        summary = {
            "attempts": agg["attempts"], "average": round(float(agg["average"] or 0), 1), "seconds": agg["seconds"],
            "active_days": agg["active_days"], "completed": sum(1 for row in rows if row["completed"]),
            "today_attempts": today["attempts"], "today_average": round(float(today["average"] or 0), 1), "today_seconds": today["seconds"],
            "today_xp": round(float(today["average"] or 0) * today["attempts"] / 5),
            "yesterday_attempts": yesterday["attempts"], "yesterday_average": round(float(yesterday["average"] or 0), 1), "yesterday_seconds": yesterday["seconds"],
            "yesterday_xp": round(float(yesterday["average"] or 0) * yesterday["attempts"] / 5),
            "week_seconds": week["seconds"], "week_goal_seconds": 1200, "joined_at": current["created_at"],
        }
        return respond({"progress": rows, "summary": summary})


@app.get("/api/admin/<path:action>")
def api_admin_get(action):
    current = require_admin()
    if not current:
        return respond({"error": "forbidden"}, 403)
    with connection() as conn:
        if action == "stats":
            if DATABASE_URL:
                active = "created_at >= NOW() - INTERVAL '7 days'"
            else:
                active = "created_at >= datetime('now','-7 day')"
            result = {
                "students": one(conn, "SELECT COUNT(*) AS n FROM users WHERE role='student'")["n"],
                "attempts": one(conn, "SELECT COUNT(*) AS n FROM attempts")["n"],
                "average": round(float(one(conn, "SELECT COALESCE(AVG(score),0) AS n FROM attempts")["n"] or 0), 2),
                "active_7d": one(conn, f"SELECT COUNT(DISTINCT user_id) AS n FROM attempts WHERE {active}")["n"],
            }
            return respond(result)
        if action == "lessons":
            return respond({"lessons": all_rows(conn, "SELECT id,title,unit,content_json FROM lessons ORDER BY unit,title")})
        if action == "students":
            return respond({"students": all_rows(conn, """SELECT u.id,u.email,u.name,u.created_at,COUNT(a.id) AS attempts,
                COALESCE(AVG(a.score),0) AS average FROM users u LEFT JOIN attempts a ON a.user_id=u.id
                WHERE u.role='student' GROUP BY u.id ORDER BY u.created_at DESC""")})
        if action == "attempts":
            return respond({"attempts": all_rows(conn, """SELECT a.id,u.email,u.name,a.lesson_id,a.score,a.duration,a.created_at
                FROM attempts a JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 200""")})
        if action == "messages":
            return respond({"messages": all_rows(conn, """SELECT m.id,u.name,u.email,m.message,m.status,m.created_at
                FROM support_messages m JOIN users u ON u.id=m.user_id ORDER BY m.created_at DESC LIMIT 200""")})
    return respond({"error": "not_found"}, 404)


def _login(conn, email: str, password: str):
    record = one(conn, "SELECT * FROM users WHERE email=?", (email,))
    if not record or not check_pw(password, record.get("password_hash")):
        return respond({"error": "Email hoặc mật khẩu không đúng"}, 401)
    token = secrets.token_urlsafe(32)
    execute(conn, "INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)", (token, record["id"], int(time.time()) + 86400 * 14))
    safe = {k: record[k] for k in ("id", "email", "name", "role", "verified", "created_at")}
    return respond({"user": safe}, session_token=token)


@app.post("/api/<path:action>")
def api_post(action):
    data = request.get_json(silent=True) or {}
    try:
        with connection() as conn:
            if action == "register":
                email = str(data.get("email", "")).strip().lower()
                name = str(data.get("name", "")).strip() or email.split("@")[0]
                password = str(data.get("password", ""))
                if "@" not in email or len(password) < 6:
                    return respond({"error": "Email hợp lệ và mật khẩu ít nhất 6 ký tự"}, 400)
                execute(conn, "INSERT INTO users(email,name,password_hash,role,verified) VALUES(?,?,?,?,1)",
                        (email, name, hash_pw(password), "student"))
                return _login(conn, email, password)

            if action == "login":
                return _login(conn, str(data.get("email", "")).lower().strip(), str(data.get("password", "")))

            if action == "logout":
                token = request.cookies.get("session", "").strip()
                if token:
                    execute(conn, "DELETE FROM sessions WHERE token=?", (token,))
                return respond({"ok": True}, clear_session=True)

            if action == "change-password":
                current = get_user()
                if not current:
                    return respond({"error": "Vui lòng đăng nhập lại."}, 401)
                old = str(data.get("current_password", ""))
                new = str(data.get("new_password", ""))
                if len(new) < 6:
                    return respond({"error": "Mật khẩu mới phải có ít nhất 6 ký tự."}, 400)
                if not check_pw(old, current.get("password_hash")):
                    return respond({"error": "Mật khẩu hiện tại không đúng."}, 400)
                execute(conn, "UPDATE users SET password_hash=? WHERE id=?", (hash_pw(new), current["id"]))
                return respond({"ok": True})

            if action == "contact":
                current = get_user()
                if not current:
                    return respond({"error": "Vui lòng đăng nhập để gửi liên hệ."}, 401)
                message = str(data.get("message", "")).strip()
                if len(message) < 10 or len(message) > 2000:
                    return respond({"error": "Nội dung cần từ 10 đến 2000 ký tự."}, 400)
                execute(conn, "INSERT INTO support_messages(user_id,message) VALUES(?,?)", (current["id"], message))
                return respond({"ok": True, "message": "Đã gửi liên hệ."}, 201)

            if action == "forgot":
                email = str(data.get("email", "")).lower().strip()
                record = one(conn, "SELECT id FROM users WHERE email=? AND role='student'", (email,))
                if record:
                    token = secrets.token_urlsafe(24)
                    execute(conn, "INSERT INTO reset_tokens(token,user_id,expires,used) VALUES(?,?,?,0)",
                            (token, record["id"], int(time.time()) + 900))
                return respond({"ok": True, "message": "Nếu tài khoản tồn tại, hướng dẫn đặt lại mật khẩu sẽ được gửi khi dịch vụ email được cấu hình."})

            if action == "reset":
                token = str(data.get("token", ""))
                record = one(conn, "SELECT * FROM reset_tokens WHERE token=? AND used=0 AND expires>?", (token, int(time.time())))
                if not record or data.get("code") != data.get("expected_code") or len(str(data.get("password", ""))) < 6:
                    return respond({"error": "Mã hoặc liên kết không hợp lệ"}, 400)
                execute(conn, "UPDATE users SET password_hash=? WHERE id=?", (hash_pw(str(data["password"])), record["user_id"]))
                execute(conn, "UPDATE reset_tokens SET used=1 WHERE token=?", (token,))
                return respond({"ok": True})

            if action.startswith("admin/"):
                current = require_admin()
                if not current:
                    return respond({"error": "forbidden"}, 403)
                admin_action = action[len("admin/"):]
                if admin_action == "messages/read":
                    execute(conn, "UPDATE support_messages SET status='Đã xử lý' WHERE id=?", (int(data.get("id", 0)),))
                    return respond({"ok": True})

                if admin_action in ("lessons/create", "lessons/update", "lessons/delete"):
                    lesson_id = str(data.get("id", "")).strip()
                    if admin_action.endswith("/create"):
                        if not lesson_id or not data.get("title") or not data.get("unit"):
                            return respond({"error": "Thiếu mã, tiêu đề hoặc Unit"}, 400)
                        content = data.get("content_json") or json.dumps({"questions": []}, ensure_ascii=False)
                        execute(conn, "INSERT INTO lessons(id,title,unit,content_json) VALUES(?,?,?,?)", (lesson_id, data["title"], data["unit"], content))
                        return respond({"ok": True}, 201)
                    if not lesson_id:
                        return respond({"error": "Thiếu mã bài học"}, 400)
                    if admin_action.endswith("/delete"):
                        execute(conn, "DELETE FROM lessons WHERE id=?", (lesson_id,))
                        return respond({"ok": True})
                    execute(conn, "UPDATE lessons SET title=?,unit=?,content_json=? WHERE id=?",
                            (data.get("title"), data.get("unit"), data.get("content_json", '{"questions":[]}'), lesson_id))
                    return respond({"ok": True})

                if admin_action in ("modules/create", "modules/update", "modules/delete"):
                    module_id = str(data.get("id", "")).strip()
                    if admin_action.endswith("/create"):
                        execute(conn, "INSERT INTO modules(id,lesson_id,title,skill,minutes,sort_order) VALUES(?,?,?,?,?,?)",
                                (module_id, data["lesson_id"], data["title"], data["skill"], int(data.get("minutes", 5)), int(data.get("sort_order", 0))))
                        return respond({"ok": True}, 201)
                    if admin_action.endswith("/delete"):
                        execute(conn, "DELETE FROM modules WHERE id=?", (module_id,))
                        return respond({"ok": True})
                    execute(conn, "UPDATE modules SET title=?,skill=?,minutes=?,sort_order=? WHERE id=?",
                            (data["title"], data["skill"], int(data.get("minutes", 5)), int(data.get("sort_order", 0)), module_id))
                    return respond({"ok": True})

                if admin_action in ("items/create", "items/update", "items/delete"):
                    item_id = str(data.get("id", "")).strip()
                    if admin_action.endswith("/create"):
                        execute(conn, """INSERT INTO items(id,module_id,item_type,prompt,answer,options_json,media_url,rubric_json,sort_order)
                            VALUES(?,?,?,?,?,?,?,?,?)""",
                            (item_id, data["module_id"], data["item_type"], data["prompt"], data.get("answer"),
                             json.dumps(data.get("options", []), ensure_ascii=False), data.get("media_url"),
                             json.dumps(data.get("rubric", {}), ensure_ascii=False), int(data.get("sort_order", 0))))
                        return respond({"ok": True}, 201)
                    if admin_action.endswith("/delete"):
                        execute(conn, "DELETE FROM items WHERE id=?", (item_id,))
                        return respond({"ok": True})
                    execute(conn, """UPDATE items SET item_type=?,prompt=?,answer=?,options_json=?,media_url=?,rubric_json=?,sort_order=? WHERE id=?""",
                            (data["item_type"], data["prompt"], data.get("answer"), json.dumps(data.get("options", []), ensure_ascii=False),
                             data.get("media_url"), json.dumps(data.get("rubric", {}), ensure_ascii=False), int(data.get("sort_order", 0)), item_id))
                    return respond({"ok": True})
                return respond({"error": "not_found"}, 404)

            if action == "attempt":
                current = get_user()
                if not current:
                    return respond({"error": "unauthorized"}, 401)
                lesson_id = str(data.get("lesson_id", "u1-vocab"))
                score = float(data.get("score", 0))
                duration = max(0, int(data.get("duration", 0)))
                completed = int(bool(data.get("completed", 1)))
                execute(conn, "INSERT INTO attempts(user_id,lesson_id,score,duration) VALUES(?,?,?,?)",
                        (current["id"], lesson_id, score, duration))
                best_expr = "GREATEST(progress.best_score, excluded.best_score)" if DATABASE_URL else "MAX(progress.best_score, excluded.best_score)"
                execute(conn, f"""INSERT INTO progress(user_id,lesson_id,completed,best_score,seconds) VALUES(?,?,?,?,?)
                    ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=excluded.completed,best_score={best_expr},
                    seconds=progress.seconds+excluded.seconds,updated_at=CURRENT_TIMESTAMP""",
                        (current["id"], lesson_id, completed, score, duration))
                return respond({"ok": True})

            return respond({"error": "not_found"}, 404)

    except Exception as exc:
        # Integrity errors are reported without leaking SQL statements or database details.
        error_name = type(exc).__name__.lower()
        if "integrity" in error_name or "uniqueviolation" in error_name or "foreignkeyviolation" in error_name:
            return respond({"error": "Email đã tồn tại hoặc dữ liệu không hợp lệ."}, 409)
        app.logger.exception("G-STUDY API error")
        return respond({"error": "Máy chủ gặp lỗi khi xử lý yêu cầu."}, 500)


@app.errorhandler(404)
def not_found(_error):
    return respond({"error": "not_found"}, 404)


@app.get("/health")
def health():
    return respond({"ok": True, "app": "G-STUDY", "database_configured": bool(DATABASE_URL)})


if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8090")), debug=False)

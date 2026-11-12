"""GymFlow - SaaS multi-tenant para la gestion de gimnasios.

Cada gimnasio (tenant) tiene sus propios usuarios, socios, planes, clases y
registros. Toda consulta SQL filtra por gym_id para garantizar el aislamiento.
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("America/Santiago")
except Exception:  # pragma: no cover
    TZ = None

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,120}\.[^@\s]{2,}$")
PHONE_RE = re.compile(r"^[0-9+\- ]{0,20}$")
MAX_ATTEMPTS = 5
LOCK_SECONDS = 600
DUMMY_HASH = generate_password_hash(secrets.token_hex(8))

SCHEMA = """
CREATE TABLE IF NOT EXISTS gyms(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','staff')),
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS plans(
  id INTEGER PRIMARY KEY,
  gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
  name TEXT NOT NULL, price INTEGER NOT NULL CHECK(price >= 0),
  duration_days INTEGER NOT NULL CHECK(duration_days > 0));
CREATE TABLE IF NOT EXISTS members(
  id INTEGER PRIMARY KEY,
  gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
  name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '',
  plan_id INTEGER NOT NULL REFERENCES plans(id),
  start_date TEXT NOT NULL, end_date TEXT NOT NULL,
  consent_at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS classes(
  id INTEGER PRIMARY KEY,
  gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
  name TEXT NOT NULL, trainer TEXT NOT NULL, starts_at TEXT NOT NULL,
  capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1 AND 200));
CREATE TABLE IF NOT EXISTS bookings(
  id INTEGER PRIMARY KEY,
  gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  UNIQUE(class_id, member_id));
CREATE TABLE IF NOT EXISTS checkins(
  id INTEGER PRIMARY KEY,
  gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  day TEXT NOT NULL, ts TEXT NOT NULL, UNIQUE(member_id, day));
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY, gym_id INTEGER, user_id INTEGER,
  action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL);
"""


# ---------------------------------------------------------------- utilidades
def now():
    return datetime.now(TZ) if TZ else datetime.utcnow()


def today():
    return now().date()


def clean(value, limit):
    """Normaliza texto de entrada: recorta espacios y limita el largo."""
    return " ".join((value or "").split())[:limit]


def password_error(pw):
    if len(pw) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        return "La contraseña debe combinar letras y números."
    return None


def db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def one(sql, args=()):
    return db().execute(sql, args).fetchone()


def many(sql, args=()):
    return db().execute(sql, args).fetchall()


def run(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur


def audit(action, detail="", gym_id=None, user_id=None):
    if g.get("user") is not None:
        gym_id = gym_id or g.user["gym_id"]
        user_id = user_id or g.user["id"]
    run("INSERT INTO audit_log(gym_id,user_id,action,detail,ip,ts) VALUES(?,?,?,?,?,?)",
        (gym_id, user_id, action, detail[:200], request.remote_addr or "",
         now().strftime("%Y-%m-%d %H:%M:%S")))


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if g.user is None:
            return redirect(url_for("login"))
        return f(*a, **k)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if g.user is None:
            return redirect(url_for("login"))
        if g.user["role"] != "admin":
            abort(403)
        return f(*a, **k)
    return wrapper


def get_member(member_id):
    """Busca un socio SOLO dentro del gimnasio del usuario (aislamiento)."""
    m = one("SELECT * FROM members WHERE id=? AND gym_id=?", (member_id, g.user["gym_id"]))
    if m is None:
        abort(404)
    return m


def get_plan(plan_id):
    return one("SELECT * FROM plans WHERE id=? AND gym_id=?", (plan_id, g.user["gym_id"]))


def login_user(user):
    session.clear()
    session["uid"] = user["id"]
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True


# ------------------------------------------------------------------ fabrica
def create_app(config=None):
    app = Flask(__name__)
    secret = os.environ.get("SECRET_KEY")
    if not secret and os.environ.get("FORCE_HTTPS") == "1":
        # En produccion una clave aleatoria por proceso rompe las sesiones
        # (cada worker de gunicorn tendria una distinta): se exige definirla.
        raise RuntimeError("Define la variable de entorno SECRET_KEY en produccion.")
    app.config.update(
        SECRET_KEY=secret or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE_PATH",
                                os.path.join(app.instance_path, "gymflow.db")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FORCE_HTTPS", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if config:
        app.config.update(config)
    if os.environ.get("TRUST_PROXY") == "1":
        # Detras del proxy del proveedor (Render) la IP real del cliente viene en
        # X-Forwarded-For; solo se confia en ella cuando se activa explicitamente.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    os.makedirs(os.path.dirname(app.config["DATABASE"]) or ".", exist_ok=True)
    with sqlite3.connect(app.config["DATABASE"]) as con:
        con.executescript(SCHEMA)

    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        uid = session.get("uid")
        if uid:
            g.user = one("SELECT id,gym_id,email,role FROM users WHERE id=?", (uid,))
            if g.user is None:
                session.clear()
        if request.method == "POST":
            expected = session.get("csrf", "")
            sent = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
                abort(400)

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.context_processor
    def inject():
        def csrf_token():
            if "csrf" not in session:
                session["csrf"] = secrets.token_urlsafe(32)
            return session["csrf"]
        return dict(csrf_token=csrf_token, today=today().isoformat())

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if g.get("user") is not None:
            resp.headers["Cache-Control"] = "no-store"
        return resp

    for code, msg in ((400, "Solicitud inválida o sesión expirada. Vuelve a intentarlo."),
                      (403, "No tienes permiso para acceder a esta sección."),
                      (404, "No encontramos lo que buscas."),
                      (413, "La solicitud es demasiado grande."),
                      (500, "Ocurrió un error interno. Intenta nuevamente.")):
        app.register_error_handler(
            code, lambda e, c=code, m=msg: (render_template("error.html", code=c, message=m), c))

    # --------------------------------------------------------- autenticacion
    @app.get("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            gym = clean(request.form.get("gym_name"), 80)
            email = clean(request.form.get("email"), 120).lower()
            pw = request.form.get("password", "")[:200]
            error = None
            if len(gym) < 2:
                error = "Ingresa el nombre del gimnasio."
            elif not EMAIL_RE.match(email):
                error = "Ingresa un correo válido."
            elif pw != request.form.get("confirm", ""):
                error = "Las contraseñas no coinciden."
            else:
                error = password_error(pw)
            if not error and one("SELECT 1 FROM users WHERE email=?", (email,)):
                error = "No se pudo crear la cuenta con esos datos."
            if error:
                flash(error, "error")
                return render_template("register.html", gym_name=gym, email=email), 400
            ts = now().strftime("%Y-%m-%d %H:%M:%S")
            gym_id = run("INSERT INTO gyms(name,created_at) VALUES(?,?)", (gym, ts)).lastrowid
            uid = run("INSERT INTO users(gym_id,email,password_hash,role,created_at) "
                      "VALUES(?,?,?,?,?)",
                      (gym_id, email, generate_password_hash(pw), "admin", ts)).lastrowid
            for n, p, d in (("Mensual", 30000, 30), ("Trimestral", 80000, 90), ("Anual", 280000, 365)):
                run("INSERT INTO plans(gym_id,name,price,duration_days) VALUES(?,?,?,?)",
                    (gym_id, n, p, d))
            audit("register", f"gimnasio '{gym}' creado", gym_id=gym_id, user_id=uid)
            login_user({"id": uid})
            flash("¡Cuenta creada! Ya puedes registrar socios.", "ok")
            return redirect(url_for("dashboard"))
        return render_template("register.html", gym_name="", email="")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = clean(request.form.get("email"), 120).lower()
            pw = request.form.get("password", "")[:200]
            user = one("SELECT * FROM users WHERE email=?", (email,))
            if user and user["locked_until"] > time.time():
                audit("login_locked", email, gym_id=user["gym_id"], user_id=user["id"])
                flash("Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.", "error")
                return render_template("login.html"), 429
            valid = check_password_hash(user["password_hash"] if user else DUMMY_HASH, pw)
            if user and valid:
                run("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (user["id"],))
                login_user(user)
                audit("login_ok", "", gym_id=user["gym_id"], user_id=user["id"])
                return redirect(url_for("dashboard"))
            if user:
                attempts = user["failed_attempts"] + 1
                locked = time.time() + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
                run("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                    (0 if locked else attempts, locked, user["id"]))
                audit("login_fail", email, gym_id=user["gym_id"], user_id=user["id"])
            flash("Correo o contraseña incorrectos.", "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        if g.user:
            audit("logout")
        session.clear()
        return redirect(url_for("index"))

    # ------------------------------------------------------------- dashboard
    @app.get("/dashboard")
    @login_required
    def dashboard():
        gid, t = g.user["gym_id"], today()
        ts = t.isoformat()
        stats = {
            "active": one("SELECT COUNT(*) c FROM members WHERE gym_id=? AND end_date>=?", (gid, ts))["c"],
            "expired": one("SELECT COUNT(*) c FROM members WHERE gym_id=? AND end_date<?", (gid, ts))["c"],
            "today": one("SELECT COUNT(*) c FROM checkins WHERE gym_id=? AND day=?", (gid, ts))["c"],
        }
        since = (t - timedelta(days=6)).isoformat()
        rows = {r["day"]: r["c"] for r in many(
            "SELECT day, COUNT(*) c FROM checkins WHERE gym_id=? AND day>=? GROUP BY day", (gid, since))}
        week = [((t - timedelta(days=i)).isoformat(), rows.get((t - timedelta(days=i)).isoformat(), 0))
                for i in range(6, -1, -1)]
        soon = many("SELECT id,name,end_date FROM members WHERE gym_id=? AND end_date BETWEEN ? AND ? "
                    "ORDER BY end_date LIMIT 8", (gid, ts, (t + timedelta(days=7)).isoformat()))
        classes = many(
            "SELECT c.*, (SELECT COUNT(*) FROM bookings b WHERE b.class_id=c.id) AS booked "
            "FROM classes c WHERE c.gym_id=? AND c.starts_at>=? ORDER BY c.starts_at LIMIT 5",
            (gid, now().strftime("%Y-%m-%d %H:%M")))
        gym = one("SELECT name FROM gyms WHERE id=?", (gid,))
        return render_template("dashboard.html", stats=stats, week=week, soon=soon,
                               classes=classes, gym=gym, max_week=max([c for _, c in week] + [1]))

    # ---------------------------------------------------------------- socios
    def read_member_form():
        name = clean(request.form.get("name"), 80)
        email = clean(request.form.get("email"), 120).lower()
        phone = clean(request.form.get("phone"), 20)
        if len(name) < 2:
            return None, "Ingresa el nombre del socio."
        if not EMAIL_RE.match(email):
            return None, "Ingresa un correo válido."
        if not PHONE_RE.match(phone):
            return None, "El teléfono solo puede tener números, +, - y espacios."
        return (name, email, phone), None

    @app.route("/members", methods=["GET", "POST"])
    @login_required
    def members():
        gid = g.user["gym_id"]
        plans = many("SELECT * FROM plans WHERE gym_id=? ORDER BY duration_days", (gid,))
        if request.method == "POST":
            data, error = read_member_form()
            plan = get_plan(request.form.get("plan_id", type=int))
            if not error and plan is None:
                error = "Selecciona un plan válido."
            if not error and not request.form.get("consent"):
                error = "Debes confirmar el consentimiento del socio para tratar sus datos."
            if error:
                flash(error, "error")
            else:
                start = today()
                end = start + timedelta(days=plan["duration_days"])
                stamp = now().strftime("%Y-%m-%d %H:%M:%S")
                mid = run("INSERT INTO members(gym_id,name,email,phone,plan_id,start_date,end_date,"
                          "consent_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          (gid, *data, plan["id"], start.isoformat(), end.isoformat(),
                           stamp, stamp)).lastrowid
                audit("member_create", f"socio #{mid}")
                flash("Socio registrado.", "ok")
                return redirect(url_for("members"))
        q = clean(request.args.get("q"), 60)
        status = request.args.get("status", "")
        sql = ("SELECT m.*, p.name AS plan_name FROM members m JOIN plans p ON p.id=m.plan_id "
               "WHERE m.gym_id=?")
        args = [gid]
        if q:
            sql += " AND (m.name LIKE ? OR m.email LIKE ?)"
            args += [f"%{q}%", f"%{q}%"]
        if status == "active":
            sql += " AND m.end_date>=?"
            args.append(today().isoformat())
        elif status == "expired":
            sql += " AND m.end_date<?"
            args.append(today().isoformat())
        rows = many(sql + " ORDER BY m.name LIMIT 200", args)
        return render_template("members.html", rows=rows, plans=plans, q=q, status=status)

    @app.route("/members/<int:member_id>", methods=["GET", "POST"])
    @login_required
    def member_detail(member_id):
        m = get_member(member_id)
        if request.method == "POST":
            data, error = read_member_form()
            if error:
                flash(error, "error")
            else:
                run("UPDATE members SET name=?, email=?, phone=? WHERE id=? AND gym_id=?",
                    (*data, m["id"], g.user["gym_id"]))
                audit("member_update", f"socio #{m['id']}")
                flash("Datos actualizados.", "ok")
                return redirect(url_for("member_detail", member_id=m["id"]))
        plans = many("SELECT * FROM plans WHERE gym_id=? ORDER BY duration_days", (g.user["gym_id"],))
        plan = one("SELECT name FROM plans WHERE id=?", (m["plan_id"],))
        visits = many("SELECT day FROM checkins WHERE member_id=? AND gym_id=? ORDER BY day DESC LIMIT 10",
                      (m["id"], g.user["gym_id"]))
        return render_template("member_detail.html", m=m, plans=plans, plan=plan, visits=visits)

    @app.post("/members/<int:member_id>/renew")
    @login_required
    def member_renew(member_id):
        m = get_member(member_id)
        plan = get_plan(request.form.get("plan_id", type=int))
        if plan is None:
            flash("Selecciona un plan válido.", "error")
        else:
            base = max(today(), datetime.strptime(m["end_date"], "%Y-%m-%d").date())
            new_end = base + timedelta(days=plan["duration_days"])
            run("UPDATE members SET plan_id=?, end_date=? WHERE id=? AND gym_id=?",
                (plan["id"], new_end.isoformat(), m["id"], g.user["gym_id"]))
            audit("member_renew", f"socio #{m['id']} hasta {new_end}")
            flash(f"Membresía renovada hasta {new_end.isoformat()}.", "ok")
        return redirect(url_for("member_detail", member_id=m["id"]))

    @app.post("/members/<int:member_id>/delete")
    @admin_required
    def member_delete(member_id):
        m = get_member(member_id)
        run("DELETE FROM members WHERE id=? AND gym_id=?", (m["id"], g.user["gym_id"]))
        audit("member_delete", f"socio #{m['id']} eliminado (derecho de supresión)")
        flash("Socio y sus registros fueron eliminados.", "ok")
        return redirect(url_for("members"))

    # ----------------------------------------------------------------- planes
    @app.route("/plans", methods=["GET", "POST"])
    @admin_required
    def plans():
        gid = g.user["gym_id"]
        if request.method == "POST":
            name = clean(request.form.get("name"), 40)
            price = request.form.get("price", type=int)
            days = request.form.get("duration_days", type=int)
            if len(name) < 2 or price is None or not 0 <= price <= 10_000_000 \
                    or days is None or not 1 <= days <= 3650:
                flash("Revisa el nombre, el precio y la duración del plan.", "error")
            else:
                run("INSERT INTO plans(gym_id,name,price,duration_days) VALUES(?,?,?,?)",
                    (gid, name, price, days))
                audit("plan_create", name)
                flash("Plan creado.", "ok")
                return redirect(url_for("plans"))
        rows = many("SELECT * FROM plans WHERE gym_id=? ORDER BY duration_days", (gid,))
        return render_template("plans.html", rows=rows)

    @app.post("/plans/<int:plan_id>/delete")
    @admin_required
    def plan_delete(plan_id):
        if get_plan(plan_id) is None:
            abort(404)
        try:
            run("DELETE FROM plans WHERE id=? AND gym_id=?", (plan_id, g.user["gym_id"]))
            audit("plan_delete", f"plan #{plan_id}")
            flash("Plan eliminado.", "ok")
        except sqlite3.IntegrityError:
            flash("No se puede eliminar: hay socios usando este plan.", "error")
        return redirect(url_for("plans"))

    # ------------------------------------------------------------------ check-in
    @app.route("/checkin", methods=["GET", "POST"])
    @login_required
    def checkin():
        gid, t = g.user["gym_id"], today().isoformat()
        if request.method == "POST":
            m = get_member(request.form.get("member_id", type=int) or 0)
            if m["end_date"] < t:
                audit("checkin_denied", f"socio #{m['id']} membresía vencida")
                flash(f"Acceso denegado: la membresía de {m['name']} venció el {m['end_date']}.", "error")
            else:
                try:
                    run("INSERT INTO checkins(gym_id,member_id,day,ts) VALUES(?,?,?,?)",
                        (gid, m["id"], t, now().strftime("%H:%M:%S")))
                    audit("checkin", f"socio #{m['id']}")
                    flash(f"Ingreso registrado: {m['name']}.", "ok")
                except sqlite3.IntegrityError:
                    flash(f"{m['name']} ya registró su ingreso hoy.", "info")
            return redirect(url_for("checkin"))
        options = many("SELECT id,name,end_date FROM members WHERE gym_id=? ORDER BY name", (gid,))
        visits = many("SELECT c.ts, m.name FROM checkins c JOIN members m ON m.id=c.member_id "
                      "WHERE c.gym_id=? AND c.day=? ORDER BY c.ts DESC", (gid, t))
        return render_template("checkin.html", options=options, visits=visits)

    # ------------------------------------------------------------------- clases
    @app.route("/classes", methods=["GET", "POST"])
    @login_required
    def classes():
        gid = g.user["gym_id"]
        if request.method == "POST":
            name = clean(request.form.get("name"), 60)
            trainer = clean(request.form.get("trainer"), 60)
            cap = request.form.get("capacity", type=int)
            try:
                starts = datetime.strptime(request.form.get("starts_at", ""), "%Y-%m-%dT%H:%M")
            except ValueError:
                starts = None
            if len(name) < 2 or len(trainer) < 2 or starts is None or cap is None or not 1 <= cap <= 200:
                flash("Revisa el nombre, entrenador, fecha y cupos de la clase.", "error")
            else:
                run("INSERT INTO classes(gym_id,name,trainer,starts_at,capacity) VALUES(?,?,?,?,?)",
                    (gid, name, trainer, starts.strftime("%Y-%m-%d %H:%M"), cap))
                audit("class_create", name)
                flash("Clase creada.", "ok")
                return redirect(url_for("classes"))
        rows = many("SELECT c.*, (SELECT COUNT(*) FROM bookings b WHERE b.class_id=c.id) AS booked "
                    "FROM classes c WHERE c.gym_id=? AND c.starts_at>=? ORDER BY c.starts_at LIMIT 100",
                    (gid, now().strftime("%Y-%m-%d %H:%M")))
        return render_template("classes.html", rows=rows)

    def get_class(class_id):
        c = one("SELECT * FROM classes WHERE id=? AND gym_id=?", (class_id, g.user["gym_id"]))
        if c is None:
            abort(404)
        return c

    @app.get("/classes/<int:class_id>")
    @login_required
    def class_detail(class_id):
        c = get_class(class_id)
        gid = g.user["gym_id"]
        attendees = many("SELECT b.id, m.name FROM bookings b JOIN members m ON m.id=b.member_id "
                         "WHERE b.class_id=? AND b.gym_id=? ORDER BY m.name", (c["id"], gid))
        options = many("SELECT id,name FROM members WHERE gym_id=? AND end_date>=? ORDER BY name",
                       (gid, today().isoformat()))
        return render_template("class_detail.html", c=c, attendees=attendees, options=options)

    @app.post("/classes/<int:class_id>/book")
    @login_required
    def class_book(class_id):
        c = get_class(class_id)
        m = get_member(request.form.get("member_id", type=int) or 0)
        if m["end_date"] < today().isoformat():
            flash("La membresía del socio está vencida.", "error")
        else:
            try:
                cur = run("INSERT INTO bookings(gym_id,class_id,member_id) "
                          "SELECT ?, c.id, ? FROM classes c WHERE c.id=? AND c.gym_id=? "
                          "AND (SELECT COUNT(*) FROM bookings b WHERE b.class_id=c.id) < c.capacity",
                          (g.user["gym_id"], m["id"], c["id"], g.user["gym_id"]))
                if cur.rowcount == 0:
                    flash("La clase no tiene cupos disponibles.", "error")
                else:
                    audit("booking_create", f"clase #{c['id']} socio #{m['id']}")
                    flash(f"Reserva confirmada para {m['name']}.", "ok")
            except sqlite3.IntegrityError:
                flash("El socio ya tiene una reserva en esta clase.", "info")
        return redirect(url_for("class_detail", class_id=c["id"]))

    @app.post("/bookings/<int:booking_id>/cancel")
    @login_required
    def booking_cancel(booking_id):
        b = one("SELECT * FROM bookings WHERE id=? AND gym_id=?", (booking_id, g.user["gym_id"]))
        if b is None:
            abort(404)
        run("DELETE FROM bookings WHERE id=? AND gym_id=?", (b["id"], g.user["gym_id"]))
        audit("booking_cancel", f"reserva #{b['id']}")
        flash("Reserva cancelada.", "ok")
        return redirect(url_for("class_detail", class_id=b["class_id"]))

    # ------------------------------------------------------- equipo y auditoria
    @app.route("/staff", methods=["GET", "POST"])
    @admin_required
    def staff():
        gid = g.user["gym_id"]
        if request.method == "POST":
            email = clean(request.form.get("email"), 120).lower()
            pw = request.form.get("password", "")[:200]
            role = request.form.get("role")
            error = None
            if not EMAIL_RE.match(email):
                error = "Ingresa un correo válido."
            elif role not in ("admin", "staff"):
                error = "Rol inválido."
            else:
                error = password_error(pw)
            if not error and one("SELECT 1 FROM users WHERE email=?", (email,)):
                error = "No se pudo crear el usuario con esos datos."
            if error:
                flash(error, "error")
            else:
                run("INSERT INTO users(gym_id,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                    (gid, email, generate_password_hash(pw), role, now().strftime("%Y-%m-%d %H:%M:%S")))
                audit("user_create", f"{email} ({role})")
                flash("Usuario creado.", "ok")
                return redirect(url_for("staff"))
        rows = many("SELECT id,email,role FROM users WHERE gym_id=? ORDER BY email", (gid,))
        return render_template("staff.html", rows=rows)

    @app.post("/staff/<int:user_id>/delete")
    @admin_required
    def staff_delete(user_id):
        if user_id == g.user["id"]:
            flash("No puedes eliminar tu propio usuario.", "error")
        else:
            cur = run("DELETE FROM users WHERE id=? AND gym_id=?", (user_id, g.user["gym_id"]))
            if cur.rowcount:
                audit("user_delete", f"usuario #{user_id}")
                flash("Usuario eliminado.", "ok")
            else:
                abort(404)
        return redirect(url_for("staff"))

    @app.get("/audit")
    @admin_required
    def audit_view():
        rows = many("SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON u.id=a.user_id "
                    "WHERE a.gym_id=? ORDER BY a.id DESC LIMIT 100", (g.user["gym_id"],))
        return render_template("audit.html", rows=rows)

    return app


if __name__ == "__main__":
    create_app().run(debug=False, port=int(os.environ.get("PORT", 5000)))

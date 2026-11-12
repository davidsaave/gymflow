"""Crea un gimnasio de demostracion. Uso: python seed.py"""
from datetime import timedelta
from werkzeug.security import generate_password_hash
from app import create_app, now, today

DEMO_EMAIL = "demo@gymflow.cl"
DEMO_PASSWORD = "Demo12345678"   # solo para demostracion local; no usar en produccion

app = create_app()
with app.app_context():
    from app import db, one, run
    if one("SELECT 1 FROM users WHERE email=?", (DEMO_EMAIL,)):
        print("La demo ya existe.")
        raise SystemExit
    stamp = now().strftime("%Y-%m-%d %H:%M:%S")
    gid = run("INSERT INTO gyms(name,created_at) VALUES(?,?)", ("Gimnasio Demo", stamp)).lastrowid
    run("INSERT INTO users(gym_id,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
        (gid, DEMO_EMAIL, generate_password_hash(DEMO_PASSWORD), "admin", stamp))
    plans = {}
    for n, p, d in (("Mensual", 30000, 30), ("Trimestral", 80000, 90), ("Anual", 280000, 365)):
        plans[n] = (run("INSERT INTO plans(gym_id,name,price,duration_days) VALUES(?,?,?,?)",
                        (gid, n, p, d)).lastrowid, d)
    t = today()
    people = [("Camila Rojas", "Mensual", -10), ("Diego Fuentes", "Trimestral", -40),
              ("Valentina Soto", "Anual", -100), ("Matías Pérez", "Mensual", -45),
              ("Javiera Núñez", "Mensual", -25)]
    for name, plan, offset in people:
        pid, days = plans[plan]
        start = t + timedelta(days=offset)
        run("INSERT INTO members(gym_id,name,email,phone,plan_id,start_date,end_date,consent_at,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (gid, name, name.split()[0].lower() + "@example.com", "+56 9 1234 5678", pid,
             start.isoformat(), (start + timedelta(days=days)).isoformat(), stamp, stamp))
    for name, trainer, hours in (("Spinning", "Carla", 20), ("Yoga", "Andrés", 44), ("Funcional", "Sofía", 68)):
        run("INSERT INTO classes(gym_id,name,trainer,starts_at,capacity) VALUES(?,?,?,?,?)",
            (gid, name, trainer, (now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:00"), 12))
    print(f"Demo creada: {DEMO_EMAIL} / {DEMO_PASSWORD}")

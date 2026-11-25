"""Pruebas automaticas de GymFlow: funcionalidad, aislamiento y seguridad (OWASP).

Ejecutar:  python -m unittest discover -s tests -v
"""
import os
import re
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta

from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app, now, today  # noqa: E402

PASSWORD = "ClaveSegura123"


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.faq_path = self.path + ".faqs.json"
        source_faq_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "chatbot_updates", "faqs.json")
        shutil.copyfile(source_faq_path, self.faq_path)
        self.app = create_app({
            "TESTING": True,
            "DATABASE": self.path,
            "CHATBOT_FAQ_FILE": self.faq_path,
        })

    def tearDown(self):
        try:
            os.remove(self.path)
        finally:
            if os.path.exists(self.faq_path):
                os.remove(self.faq_path)

    # ayudantes
    def token(self, client, url="/login"):
        html = client.get(url).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, client, url, data=None, page="/login", **kw):
        data = dict(data or {})
        data["csrf_token"] = self.token(client, page)
        return client.post(url, data=data, **kw)

    def register(self, gym="Gym Uno", email="admin@uno.cl"):
        c = self.app.test_client()
        r = self.post(c, "/register", {"gym_name": gym, "email": email, "password": PASSWORD,
                                       "confirm": PASSWORD}, page="/register")
        self.assertEqual(r.status_code, 302)
        return c

    def add_member(self, c, name="Ana Test", plan_id=1):
        return self.post(c, "/members", {"name": name, "email": "ana@example.com", "phone": "+56 9 1111",
                                         "plan_id": plan_id, "consent": "1"}, page="/members")


class Funcionalidad(Base):
    def test_chatbot_expone_solo_el_catalogo_publico(self):
        response = self.app.test_client().get("/api/chatbot/faqs")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["version"])
        self.assertTrue(payload["faqs"])
        self.assertEqual(set(payload["faqs"][0]), {"id", "question", "answer"})
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_cambios_de_planes_actualizan_archivo_y_api_del_chatbot(self):
        client = self.register()
        response = self.post(client, "/plans", {
            "name": "Semestral",
            "price": "150000",
            "duration_days": "180",
        }, page="/plans")
        self.assertEqual(response.status_code, 302)
        payload = client.get("/api/chatbot/faqs").get_json()
        plans = next(faq for faq in payload["faqs"] if faq["id"] == "plans")
        self.assertIn("Semestral: $150.000 CLP (180 días)", plans["answer"])

    def test_chatbot_administrador_puede_actualizar_el_catalogo_publico(self):
        client = self.register()
        response = self.post(client, "/chatbot/faqs/enrollment/update", {
            "question": "¿Cuál es la inscripción?",
            "answer": "La inscripción cuesta $12.000 CLP.",
        }, page="/chatbot/faqs")
        self.assertEqual(response.status_code, 302)
        payload = client.get("/api/chatbot/faqs").get_json()
        enrollment = next(faq for faq in payload["faqs"] if faq["id"] == "enrollment")
        self.assertEqual(enrollment["answer"], "La inscripción cuesta $12.000 CLP.")

    def test_chatbot_administrador_puede_agregar_y_eliminar_preguntas(self):
        client = self.register()
        response = self.post(client, "/chatbot/faqs/add", {
            "question": "¿Hay estacionamiento?",
            "answer": "Consulta la disponibilidad con el gimnasio.",
        }, page="/chatbot/faqs")
        self.assertEqual(response.status_code, 302)
        payload = client.get("/api/chatbot/faqs").get_json()
        added = next(faq for faq in payload["faqs"] if faq["question"] == "¿Hay estacionamiento?")

        response = self.post(client, f"/chatbot/faqs/{added['id']}/delete", page="/chatbot/faqs")
        self.assertEqual(response.status_code, 302)
        payload = client.get("/api/chatbot/faqs").get_json()
        self.assertNotIn("¿Hay estacionamiento?", [faq["question"] for faq in payload["faqs"]])

    def test_registro_crea_gimnasio_planes_y_sesion(self):
        c = self.register()
        html = c.get("/dashboard").get_data(as_text=True)
        self.assertIn("Gym Uno", html)
        self.assertIn("Mensual", c.get("/plans").get_data(as_text=True))

    def test_portada_publica_muestra_gimnasios_y_planes(self):
        owner = self.register("Gym Visible", "admin@visible.cl")
        self.post(owner, "/gym/profile", {
            "description": "Entrenamiento para toda la familia.",
            "address": "Av. Central 123",
            "phone": "+56 9 1234",
            "contact_email": "contacto@visible.cl",
            "opening_hours": "Lunes a viernes",
        }, page="/gym/profile")
        guest = self.app.test_client()
        home = guest.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn("Gym Visible", home.get_data(as_text=True))
        detail = guest.get("/gyms/1")
        self.assertIn("Mensual", detail.get_data(as_text=True))
        self.assertIn("Entrenamiento para toda la familia.", detail.get_data(as_text=True))
        self.assertIn("Av. Central 123", detail.get_data(as_text=True))
        self.assertNotIn("admin@visible.cl", detail.get_data(as_text=True))

    def test_persona_se_inscribe_y_solo_accede_a_su_portal(self):
        self.register("Gym Uno", "admin@uno.cl")
        member = self.app.test_client()
        response = self.post(member, "/register", {
            "account_type": "member",
            "name": "Socio Nuevo",
            "plan_id": "1",
            "email": "persona@example.com",
            "password": PASSWORD,
            "confirm": PASSWORD,
            "consent": "1",
        }, page="/register")
        self.assertEqual(response.status_code, 302)
        portal = member.get("/my-gym")
        self.assertEqual(portal.status_code, 200)
        self.assertIn("Socio Nuevo", portal.get_data(as_text=True))
        self.assertIn("Mensual", portal.get_data(as_text=True))
        self.assertEqual(member.get("/members").status_code, 302)
        returning_member = self.app.test_client()
        login = self.post(returning_member, "/login", {
            "email": "persona@example.com",
            "password": PASSWORD,
        })
        self.assertEqual(login.status_code, 302)
        self.assertEqual(login.location, "/my-gym")

    def test_alta_de_socio_requiere_consentimiento(self):
        c = self.register()
        r = self.post(c, "/members", {"name": "Sin Consent", "email": "x@example.com", "plan_id": 1},
                      page="/members", follow_redirects=True)
        self.assertIn("consentimiento", r.get_data(as_text=True))
        self.assertNotIn("Sin Consent", c.get("/members").get_data(as_text=True))

    def test_checkin_ok_y_duplicado(self):
        c = self.register()
        self.add_member(c)
        r = self.post(c, "/checkin", {"member_id": 1}, page="/checkin", follow_redirects=True)
        self.assertIn("Ingreso registrado", r.get_data(as_text=True))
        r = self.post(c, "/checkin", {"member_id": 1}, page="/checkin", follow_redirects=True)
        self.assertIn("ya registró", r.get_data(as_text=True))

    def test_checkin_denegado_con_membresia_vencida(self):
        c = self.register()
        self.add_member(c)
        import sqlite3
        con = sqlite3.connect(self.path)
        con.execute("UPDATE members SET end_date=?", ((today() - timedelta(days=1)).isoformat(),))
        con.commit()
        con.close()
        r = self.post(c, "/checkin", {"member_id": 1}, page="/checkin", follow_redirects=True)
        self.assertIn("Acceso denegado", r.get_data(as_text=True))

    def test_renovar_extiende_vencimiento(self):
        c = self.register()
        self.add_member(c)
        r = self.post(c, "/members/1/renew", {"plan_id": 2}, page="/members/1", follow_redirects=True)
        self.assertIn("Membresía renovada", r.get_data(as_text=True))

    def test_cupos_de_clase_son_limitados(self):
        c = self.register()
        self.add_member(c, "Socio Uno")
        self.add_member(c, "Socio Dos")
        when = (now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
        self.post(c, "/classes", {"name": "Yoga", "trainer": "Sofia", "starts_at": when, "capacity": 1},
                  page="/classes")
        r1 = self.post(c, "/classes/1/book", {"member_id": 1}, page="/classes/1", follow_redirects=True)
        self.assertIn("Reserva confirmada", r1.get_data(as_text=True))
        r2 = self.post(c, "/classes/1/book", {"member_id": 2}, page="/classes/1", follow_redirects=True)
        self.assertIn("no tiene cupos", r2.get_data(as_text=True))


class Seguridad(Base):
    def test_migracion_conserva_cuentas_existentes(self):
        fd, legacy_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            import sqlite3
            con = sqlite3.connect(legacy_path)
            con.executescript("""
                CREATE TABLE gyms(
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY,
                    gym_id INTEGER NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
                    email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','staff')),
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
                INSERT INTO gyms(id,name,created_at) VALUES(1,'Gym Antiguo','2026-01-01');
            """)
            con.execute(
                "INSERT INTO users(gym_id,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (1, "admin@antiguo.cl", generate_password_hash(PASSWORD), "admin", "2026-01-01"))
            con.commit()
            con.close()

            migrated_app = create_app({
                "TESTING": True,
                "DATABASE": legacy_path,
                "CHATBOT_FAQ_FILE": self.faq_path,
            })
            client = migrated_app.test_client()
            response = self.post(client, "/login", {
                "email": "admin@antiguo.cl",
                "password": PASSWORD,
            })
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/dashboard")
            con = sqlite3.connect(legacy_path)
            user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
            gym_columns = {row[1] for row in con.execute("PRAGMA table_info(gyms)")}
            con.close()
            self.assertIn("member_id", user_columns)
            self.assertIn("description", gym_columns)
        finally:
            if os.path.exists(legacy_path):
                os.remove(legacy_path)

    def test_a01_aislamiento_entre_gimnasios(self):
        a = self.register("Gym A", "a@a.cl")
        self.add_member(a, "Socio Secreto")
        b = self.register("Gym B", "b@b.cl")
        self.assertEqual(b.get("/members/1").status_code, 404)
        self.assertNotIn("Socio Secreto", b.get("/members").get_data(as_text=True))
        r = self.post(b, "/members/1/delete", page="/members")
        self.assertEqual(r.status_code, 404)
        self.assertIn("Socio Secreto", a.get("/members").get_data(as_text=True))

    def test_a01_rol_staff_no_accede_a_administracion(self):
        admin = self.register()
        self.post(admin, "/staff", {"email": "staff@uno.cl", "password": PASSWORD, "role": "staff"},
                  page="/staff")
        staff = self.app.test_client()
        self.post(staff, "/login", {"email": "staff@uno.cl", "password": PASSWORD})
        for url in ("/staff", "/plans", "/audit", "/chatbot/faqs"):
            self.assertEqual(staff.get(url).status_code, 403, url)

    def test_rutas_privadas_exigen_login(self):
        c = self.app.test_client()
        for url in ("/dashboard", "/members", "/checkin", "/classes"):
            self.assertEqual(c.get(url).status_code, 302, url)

    def test_csrf_bloquea_post_sin_token(self):
        c = self.register()
        r = c.post("/members", data={"name": "X", "email": "x@example.com", "plan_id": 1, "consent": "1"})
        self.assertEqual(r.status_code, 400)

    def test_a03_inyeccion_sql_en_busqueda(self):
        c = self.register()
        self.add_member(c)
        r = c.get("/members", query_string={"q": "' OR 1=1 --", "status": "x'; DROP TABLE members;--"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Ana Test", c.get("/members").get_data(as_text=True))

    def test_a03_xss_se_escapa_en_salida(self):
        c = self.register()
        self.post(c, "/members", {"name": "<script>alert(1)</script>", "email": "x@example.com",
                                  "plan_id": 1, "consent": "1"}, page="/members")
        html = c.get("/members").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_a07_politica_de_contrasenas(self):
        c = self.app.test_client()
        r = self.post(c, "/register", {"gym_name": "G", "email": "a@a.cl", "password": "corta1",
                                       "confirm": "corta1"}, page="/register")
        self.assertEqual(r.status_code, 400)
        r = self.post(c, "/register", {"gym_name": "Gym", "email": "a@a.cl", "password": "soloLetrasLargas",
                                       "confirm": "soloLetrasLargas"}, page="/register")
        self.assertEqual(r.status_code, 400)

    def test_a07_bloqueo_por_intentos_fallidos(self):
        self.register()
        c = self.app.test_client()
        for _ in range(5):
            r = self.post(c, "/login", {"email": "admin@uno.cl", "password": "incorrecta123"})
            self.assertEqual(r.status_code, 401)
        r = self.post(c, "/login", {"email": "admin@uno.cl", "password": PASSWORD})
        self.assertEqual(r.status_code, 429)

    def test_a02_contrasenas_no_se_guardan_en_claro(self):
        self.register()
        import sqlite3
        con = sqlite3.connect(self.path)
        stored = con.execute("SELECT password_hash FROM users").fetchone()[0]
        con.close()
        self.assertNotIn(PASSWORD, stored)
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_a05_cabeceras_de_seguridad(self):
        r = self.app.test_client().get("/")
        for header in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
                       "Referrer-Policy"):
            self.assertIn(header, r.headers)

    def test_a09_auditoria_registra_eventos(self):
        c = self.register()
        self.add_member(c)
        html = c.get("/audit").get_data(as_text=True)
        self.assertIn("member_create", html)
        self.assertIn("register", html)

    def test_errores_no_exponen_detalles_internos(self):
        r = self.app.test_client().get("/ruta-que-no-existe")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()

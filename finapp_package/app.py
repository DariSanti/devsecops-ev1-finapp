"""
FinApp - Portal de Gestión de Reembolsos Corporativos
Prototipo seguro desarrollado aplicando el ciclo de vida DevSecOps.

Controles de seguridad implementados:
  1. Validación estricta de entradas (Regex: RUT, montos, correo corporativo)
  2. Gestión de autenticación y sesiones (política de contraseñas + bloqueo por intentos fallidos)
  3. Control de acceso y manejo de errores (sin exposición de stack traces)
  4. Registro de intentos (para evidencias de pentesting)
"""

import os
import re
import sqlite3
import time
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuración base
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FINAPP_SECRET_KEY", os.urandom(24).hex())
app.config["DEBUG"] = False  # Nunca exponer stack traces en producción/demo
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # 3 MB máx. por comprobante
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["DATABASE"] = os.path.join(os.path.dirname(__file__), "finapp.db")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Log de seguridad (evidencia de intentos, controles disparados, etc.)
logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "security_audit.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
security_log = logging.getLogger("finapp.security")

# ---------------------------------------------------------------------------
# Persistencia en SQLite (usuarios y solicitudes)
# ---------------------------------------------------------------------------
CORPORATE_DOMAIN = "finapp.cl"

# Control de intentos fallidos de login -> Control 2 (bloqueo defensivo)
LOGIN_ATTEMPTS = {}  # username -> {"count": int, "locked_until": timestamp|None}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutos


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('empleado', 'aprobador')),
            nombre TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reembolsos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rut TEXT NOT NULL,
            email TEXT NOT NULL,
            monto INTEGER NOT NULL,
            descripcion TEXT NOT NULL,
            archivo TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'Pendiente',
            solicitante TEXT NOT NULL,
            fecha TEXT NOT NULL,
            FOREIGN KEY(solicitante) REFERENCES users(username)
        )
        """
    )
    db.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role, nombre, email) VALUES (?, ?, ?, ?, ?)",
        ("jperez", generate_password_hash("Empleado#2024"), "empleado", "Juan Pérez", f"jperez@{CORPORATE_DOMAIN}"),
    )
    db.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role, nombre, email) VALUES (?, ?, ?, ?, ?)",
        ("mgonzalez", generate_password_hash("Aprobador#2024"), "aprobador", "María González", f"mgonzalez@{CORPORATE_DOMAIN}"),
    )
    db.commit()


def get_user_by_username(username: str):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_all_users():
    return get_db().execute(
        "SELECT * FROM users ORDER BY nombre ASC"
    ).fetchall()


def create_user(username: str, password: str, nombre: str = None, role: str = "empleado", email: str = None):
    username = (username or "").strip()
    nombre = (nombre or username).strip()
    role = (role or "empleado").strip()

    if not username or not nombre:
        raise ValueError("Faltan datos obligatorios para crear el usuario.")
    if not validar_password(password):
        raise ValueError("La contraseña no cumple con la política requerida.")
    if not role or role not in {"empleado", "aprobador"}:
        raise ValueError("El rol debe ser empleado o aprobador.")

    correo_esperado = f"{username.lower()}@{CORPORATE_DOMAIN}"
    if email is None:
        email = correo_esperado
    email = email.strip()

    if not validar_email_corporativo(email):
        raise ValueError(f"El correo debe ser corporativo (@{CORPORATE_DOMAIN}).")
    if email.lower() != correo_esperado:
        raise ValueError(f"El correo se genera automáticamente como {correo_esperado}.")
    if get_user_by_username(username):
        raise ValueError("El nombre de usuario ya existe.")

    db = get_db()
    db.execute(
        "INSERT INTO users (username, password_hash, role, nombre, email) VALUES (?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), role, nombre, email.lower()),
    )
    db.commit()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def reembolsos_de(username: str):
    return get_db().execute(
        "SELECT * FROM reembolsos WHERE solicitante = ? ORDER BY id DESC",
        (username,),
    ).fetchall()


def get_all_reembolsos():
    return get_db().execute(
        "SELECT * FROM reembolsos ORDER BY id DESC"
    ).fetchall()


with app.app_context():
    init_db()

# ---------------------------------------------------------------------------
# CONTROL 1: Validación estricta de entradas (Regex)
# ---------------------------------------------------------------------------
RUT_RE = re.compile(r"^\d{7,8}-[0-9kK]$")
MONTO_RE = re.compile(r"^[1-9][0-9]{0,8}$")  # entero positivo, sin signos, hasta 999.999.999
EMAIL_CORP_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@" + re.escape(CORPORATE_DOMAIN) + r"$")
# Password: min 10 caracteres, mayúscula, minúscula, dígito y carácter especial
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$")
# Whitelist para texto libre (descripción del gasto): letras, números, espacios y puntuación básica
DESC_RE = re.compile(r"^[a-zA-Z0-9À-ÿ\s.,\-#$%()]{0,300}$")


def validar_rut(rut: str) -> bool:
    """Valida formato Y dígito verificador (Módulo 11) de un RUT chileno."""
    if not rut or not RUT_RE.match(rut.strip()):
        return False
    cuerpo, dv = rut.strip().split("-")
    dv = dv.upper()
    suma, multiplicador = 0, 2
    for c in reversed(cuerpo):
        suma += int(c) * multiplicador
        multiplicador = multiplicador + 1 if multiplicador < 7 else 2
    resto = 11 - (suma % 11)
    dv_calculado = {11: "0", 10: "K"}.get(resto, str(resto))
    return dv_calculado == dv


def validar_monto(monto: str) -> bool:
    return bool(monto) and bool(MONTO_RE.match(monto.strip())) and int(monto) <= 5_000_000


def validar_email_corporativo(email: str) -> bool:
    return bool(email) and bool(EMAIL_CORP_RE.match(email.strip()))


def validar_password(password: str) -> bool:
    return bool(password) and bool(PASSWORD_RE.match(password))


def validar_descripcion(desc: str) -> bool:
    return DESC_RE.match(desc or "") is not None


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# CONTROL 2 y 3: Autenticación, sesiones y control de acceso
# ---------------------------------------------------------------------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                security_log.warning(
                    "ACCESO DENEGADO sin sesión a %s desde %s", request.path, request.remote_addr
                )
                flash("Debe iniciar sesión para continuar.", "error")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                security_log.warning(
                    "ACCESO DENEGADO: usuario '%s' (rol %s) intentó acceder a %s (requiere %s)",
                    session.get("username"), session.get("role"), request.path, role,
                )
                return render_template("error.html", codigo=403,
                                        mensaje="No tiene permisos para acceder a este recurso."), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


def is_locked(username: str) -> bool:
    info = LOGIN_ATTEMPTS.get(username)
    if not info or not info.get("locked_until"):
        return False
    if time.time() >= info["locked_until"]:
        # El bloqueo expiró: se resetea
        LOGIN_ATTEMPTS[username] = {"count": 0, "locked_until": None}
        return False
    return True


def register_failed_attempt(username: str):
    info = LOGIN_ATTEMPTS.setdefault(username, {"count": 0, "locked_until": None})
    info["count"] += 1
    security_log.warning("LOGIN FALLIDO #%d para usuario '%s' desde %s",
                          info["count"], username, request.remote_addr)
    if info["count"] >= MAX_ATTEMPTS:
        info["locked_until"] = time.time() + LOCKOUT_SECONDS
        security_log.warning("CUENTA BLOQUEADA: '%s' por %ds tras %d intentos fallidos",
                              username, LOCKOUT_SECONDS, info["count"])


def reset_attempts(username: str):
    LOGIN_ATTEMPTS[username] = {"count": 0, "locked_until": None}


# ---------------------------------------------------------------------------
# CONTROL 3: Manejo de errores sin exponer información sensible
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", codigo=404, mensaje="Recurso no encontrado."), 404


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", codigo=403, mensaje="Acceso denegado."), 403


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", codigo=413, mensaje="El archivo supera el tamaño máximo permitido (3MB)."), 413


@app.errorhandler(500)
def server_error(e):
    # Se registra el detalle SOLO en el log interno, nunca se muestra al usuario
    security_log.error("ERROR INTERNO no controlado: %s", repr(e))
    return render_template("error.html", codigo=500,
                            mensaje="Ha ocurrido un error interno. El equipo técnico ha sido notificado."), 500


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("empleado" if session["role"] == "empleado" else "aprobador"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if is_locked(username):
            restante = int(LOGIN_ATTEMPTS[username]["locked_until"] - time.time())
            flash(f"Cuenta bloqueada temporalmente. Intente nuevamente en {restante}s.", "error")
            return render_template("login.html"), 403

        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            reset_attempts(username)
            session.clear()
            session["username"] = username
            session["role"] = user["role"]
            session["nombre"] = user["nombre"]
            security_log.info("LOGIN EXITOSO: '%s' (rol %s)", username, user["role"])
            return redirect(url_for("empleado" if user["role"] == "empleado" else "aprobador"))

        register_failed_attempt(username)
        flash("Credenciales inválidas.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    security_log.info("LOGOUT: '%s'", session.get("username"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/empleado", methods=["GET", "POST"])
@login_required(role="empleado")
def empleado():
    if request.method == "POST":
        rut = request.form.get("rut", "")
        email = request.form.get("email", "")
        monto = request.form.get("monto", "")
        descripcion = request.form.get("descripcion", "")
        archivo = request.files.get("comprobante")

        errores = []
        if not validar_rut(rut):
            errores.append("RUT inválido. Formato esperado: 12345678-9 (con dígito verificador correcto).")
        if not validar_email_corporativo(email):
            errores.append(f"El correo debe ser corporativo (@{CORPORATE_DOMAIN}).")
        if not validar_monto(monto):
            errores.append("Monto inválido. Debe ser un número entero entre 1 y 5.000.000.")
        if not validar_descripcion(descripcion):
            errores.append("La descripción contiene caracteres no permitidos o excede 300 caracteres.")
        if not archivo or archivo.filename == "":
            errores.append("Debe adjuntar un comprobante.")
        elif not allowed_file(archivo.filename):
            errores.append("Formato de comprobante no permitido (solo PNG, JPG, PDF).")

        if errores:
            security_log.warning("ENTRADA RECHAZADA para usuario '%s': %s", session["username"], errores)
            for err in errores:
                flash(err, "error")
            return render_template("empleado.html", reembolsos=reembolsos_de(session["username"])), 400

        filename = secure_filename(f"{int(time.time())}_{archivo.filename}")
        archivo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db = get_db()
        db.execute(
            "INSERT INTO reembolsos (rut, email, monto, descripcion, archivo, estado, solicitante, fecha) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (rut.strip(), email.strip(), int(monto), descripcion.strip(), filename, "Pendiente", session["username"], datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        db.commit()
        security_log.info("REEMBOLSO CREADO por '%s' monto=%s", session["username"], monto)
        flash("Solicitud de reembolso enviada correctamente.", "success")
        return redirect(url_for("empleado"))

    return render_template("empleado.html", reembolsos=reembolsos_de(session["username"]))


@app.route("/aprobador")
@login_required(role="aprobador")
def aprobador():
    return render_template("aprobador.html", reembolsos=get_all_reembolsos())


@app.route("/usuarios/registrar", methods=["GET", "POST"])
@login_required(role="aprobador")
def registrar_usuario():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        nombre = (request.form.get("nombre") or "").strip()
        role = (request.form.get("role") or "empleado").strip()
        email = (request.form.get("email") or "").strip() or None

        try:
            create_user(username, password, nombre, role, email)
            flash("Usuario registrado correctamente.", "success")
            return redirect(url_for("registrar_usuario"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("registro_usuario.html", usuarios=get_all_users()), 400

    return render_template("registro_usuario.html", usuarios=get_all_users())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        try:
            create_user(username, password)
            flash("Cuenta creada correctamente. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("login"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("register.html"), 400

    return render_template("register.html")


@app.route("/aprobador/<int:reembolso_id>/<accion>", methods=["POST"])
@login_required(role="aprobador")
def resolver(reembolso_id, accion):
    if accion not in ("aprobar", "rechazar"):
        return render_template("error.html", codigo=400, mensaje="Acción no válida."), 400

    db = get_db()
    estado = "Aprobado" if accion == "aprobar" else "Rechazado"
    db.execute("UPDATE reembolsos SET estado = ? WHERE id = ?", (estado, reembolso_id))
    db.commit()
    security_log.info("REEMBOLSO %s id=%d por '%s'", estado.upper(), reembolso_id, session["username"])
    flash(f"Solicitud #{reembolso_id} marcada como {estado}.", "success")
    return redirect(url_for("aprobador"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

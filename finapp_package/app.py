"""
FinApp - Portal de Gestión de Reembolsos Corporativos
Prototipo seguro desarrollado aplicando el ciclo de vida DevSecOps.

Controles de seguridad implementados:
  1. Login de administración independiente (/admin) aislado del portal público.
  2. Panel de administración centralizado (/admin/dashboard) para gestión de roles.
  3. Redirección estricta de usuarios autenticados según su rol (RBAC).
  4. Política de contraseñas, confirmación y validación defensiva.
  5. Bloqueo temporal por 3 minutos (180s) tras 5 intentos fallidos (sin avisos previos).
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
app.config["DEBUG"] = False
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["DATABASE"] = os.path.join(os.path.dirname(__file__), "finapp.db")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "security_audit.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
security_log = logging.getLogger("finapp.security")

CORPORATE_DOMAIN = "finapp.cl"
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 180  # 3 minutos de timeout


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
            role TEXT NOT NULL CHECK(role IN ('empleado', 'aprobador', 'admin')),
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
    # Únicamente se inicializa la cuenta de Administrador
    db.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role, nombre, email) VALUES (?, ?, ?, ?, ?)",
        ("admin", generate_password_hash("Admin#2024Secure"), "admin", "Administrador FinApp", f"admin@{CORPORATE_DOMAIN}"),
    )
    db.commit()


def get_user_by_username(username: str):
    return get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_all_users():
    return get_db().execute("SELECT * FROM users ORDER BY id ASC").fetchall()


def create_user(username: str, password: str, confirm_password: str, nombre: str = None, role: str = "empleado", email: str = None):
    username = (username or "").strip()
    nombre = (nombre or username).strip()
    role = (role or "empleado").strip()

    if not username or not nombre:
        raise ValueError("Faltan datos obligatorios para crear el usuario.")
    if password != confirm_password:
        raise ValueError("Las contraseñas no coinciden.")
    if not validar_password(password):
        raise ValueError("La contraseña no cumple con la política requerida.")
    if role not in {"empleado", "aprobador", "admin"}:
        raise ValueError("El rol especificado no es válido.")

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


def update_user_role(user_id: int, new_role: str):
    if new_role not in {"empleado", "aprobador", "admin"}:
        raise ValueError("Rol no válido.")
    
    user = get_user_by_id(user_id)
    if not user:
        raise ValueError("El usuario especificado no existe.")

    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    security_log.info("CAMBIO DE ROL: usuario '%s' actualizado a '%s'", user["username"], new_role)


def reembolsos_de(username: str):
    return get_db().execute("SELECT * FROM reembolsos WHERE solicitante = ? ORDER BY id DESC", (username,)).fetchall()


def get_all_reembolsos():
    return get_db().execute("SELECT * FROM reembolsos ORDER BY id DESC").fetchall()


with app.app_context():
    init_db()

# ---------------------------------------------------------------------------
# Validaciones Regex
# ---------------------------------------------------------------------------
RUT_RE = re.compile(r"^\d{7,8}-[0-9kK]$")
MONTO_RE = re.compile(r"^[1-9][0-9]{0,8}$")
EMAIL_CORP_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@" + re.escape(CORPORATE_DOMAIN) + r"$")
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$")
DESC_RE = re.compile(r"^[a-zA-Z0-9À-ÿ\s.,\-#$%()]{0,300}$")


def validar_rut(rut: str) -> bool:
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
# Autenticación y accesos
# ---------------------------------------------------------------------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                security_log.warning("ACCESO DENEGADO sin sesión a %s desde %s", request.path, request.remote_addr)
                flash("Debe iniciar sesión para continuar.", "error")
                return redirect(url_for("login"))
            
            current_role = session.get("role")
            if role and current_role != role:
                security_log.warning(
                    "ACCESO DENEGADO: usuario '%s' (rol %s) intentó acceder a %s (requiere %s)",
                    session.get("username"), current_role, request.path, role,
                )
                return render_template("error.html", codigo=403, mensaje="No tiene permisos para acceder a este recurso."), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


def is_locked(username: str) -> bool:
    info = LOGIN_ATTEMPTS.get(username)
    if not info or not info.get("locked_until"):
        return False
    if time.time() >= info["locked_until"]:
        LOGIN_ATTEMPTS[username] = {"count": 0, "locked_until": None}
        return False
    return True


def register_failed_attempt(username: str):
    info = LOGIN_ATTEMPTS.setdefault(username, {"count": 0, "locked_until": None})
    info["count"] += 1
    security_log.warning("LOGIN FALLIDO #%d para usuario '%s' desde %s", info["count"], username, request.remote_addr)
    if info["count"] >= MAX_ATTEMPTS:
        info["locked_until"] = time.time() + LOCKOUT_SECONDS
        security_log.warning("CUENTA BLOQUEADA: '%s' por %ds tras %d intentos fallidos", username, LOCKOUT_SECONDS, info["count"])


def reset_attempts(username: str):
    LOGIN_ATTEMPTS[username] = {"count": 0, "locked_until": None}


# ---------------------------------------------------------------------------
# Manejo de Errores
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
    security_log.error("ERROR INTERNO: %s", repr(e))
    return render_template("error.html", codigo=500, mensaje="Ha ocurrido un error interno."), 500


# ---------------------------------------------------------------------------
# Rutas y Control de Navegación
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "username" in session:
        role = session.get("role")
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif role == "aprobador":
            return redirect(url_for("aprobador"))
        return redirect(url_for("empleado"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        role = session.get("role")
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif role == "aprobador":
            return redirect(url_for("aprobador"))
        return redirect(url_for("empleado"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if is_locked(username):
            restante = int(LOGIN_ATTEMPTS[username]["locked_until"] - time.time())
            flash(
                f"Has superado el límite de 5 intentos fallidos. Tu cuenta ha sido bloqueada temporalmente por 3 minutos. Reintenta en {restante}s.",
                "error",
            )
            return render_template("login.html"), 403

        user = get_user_by_username(username)
        
        if user and user["role"] == "admin":
            flash("Las cuentas de administración deben ingresar exclusivamente por el portal /admin.", "error")
            return render_template("login.html"), 403

        if user and check_password_hash(user["password_hash"], password):
            reset_attempts(username)
            session.clear()
            session["username"] = username
            session["role"] = user["role"]
            session["nombre"] = user["nombre"]
            security_log.info("LOGIN EXITOSO: '%s' (rol %s)", username, user["role"])
            
            if user["role"] == "aprobador":
                return redirect(url_for("aprobador"))
            return redirect(url_for("empleado"))

        register_failed_attempt(username)

        if is_locked(username):
            flash(
                "Has superado el límite de 5 intentos fallidos. Se ha activado un bloqueo de seguridad de 3 minutos.",
                "error",
            )
            return render_template("login.html"), 403

        flash("Credenciales inválidas.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if is_locked(username):
            restante = int(LOGIN_ATTEMPTS[username]["locked_until"] - time.time())
            flash(
                f"Has superado el límite de 5 intentos fallidos. Acceso bloqueado por 3 minutos. Tiempo restante: {restante}s.",
                "error",
            )
            return render_template("admin_login.html"), 403

        user = get_user_by_username(username)
        
        if user and user["role"] == "admin" and check_password_hash(user["password_hash"], password):
            reset_attempts(username)
            session.clear()
            session["username"] = username
            session["role"] = user["role"]
            session["nombre"] = user["nombre"]
            security_log.info("LOGIN ADMIN EXITOSO: '%s'", username)
            return redirect(url_for("admin_dashboard"))

        register_failed_attempt(username)

        if is_locked(username):
            flash(
                "Has superado el límite de 5 intentos fallidos. Se ha activado un bloqueo de seguridad de 3 minutos.",
                "error",
            )
            return render_template("admin_login.html"), 403

        flash("Credenciales administrativas inválidas.", "error")
        return render_template("admin_login.html"), 401

    return render_template("admin_login.html")


@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", usuarios=get_all_users())


@app.route("/admin/usuarios/cambiar_rol/<int:user_id>", methods=["POST"])
@login_required(role="admin")
def cambiar_rol(user_id):
    nuevo_rol = request.form.get("role", "").strip()
    try:
        update_user_role(user_id, nuevo_rol)
        flash("Rol actualizado correctamente.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    security_log.info("LOGOUT: '%s'", session.get("username"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        try:
            create_user(username=username, password=password, confirm_password=confirm_password, role="empleado")
            flash("Cuenta creada correctamente con rol Empleado. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("login"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("register.html"), 400

    return render_template("register.html")


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
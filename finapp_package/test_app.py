import sqlite3

from app import app, init_db, create_user, get_db


def test_db_initialization_and_user_creation():
    with app.app_context():
        init_db()
        conn = get_db()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'reembolsos')"
        ).fetchall()
        assert {row[0] for row in tables} == {"users", "reembolsos"}

        create_user(
            username="nuevoempleado",
            password="Empleado#2025",
            nombre="Nuevo Empleado",
            role="empleado",
            email="nuevoempleado@finapp.cl",
        )

        user = conn.execute(
            "SELECT username, role, email FROM users WHERE username = 'nuevoempleado'"
        ).fetchone()
        assert user is not None
        assert user[1] == "empleado"
        assert user[2] == "nuevoempleado@finapp.cl"

        conn.close()

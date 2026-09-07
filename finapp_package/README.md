# FinApp - Portal de Gestión de Reembolsos Corporativos

Prototipo seguro desarrollado como Entregable 2 de la evaluación "Ciclo de Vida DevSecOps".

## Requisitos
- Python 3.10+

## Instalación y ejecución

```bash
python3 -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

La aplicación queda disponible en http://127.0.0.1:5000

## Usuarios de prueba

| Usuario     | Contraseña        | Rol        |
|-------------|-------------------|------------|
| jperez      | Empleado#2024     | empleado   |
| mgonzalez   | Aprobador#2024    | aprobador  |

## Controles de seguridad implementados

1. **Validación estricta de entradas**: RUT (formato + dígito verificador Módulo 11),
   monto (entero positivo 1-5.000.000), correo corporativo (@finapp.cl), descripción
   (whitelist de caracteres) y extensión de archivo adjunto (png/jpg/pdf).
2. **Gestión de autenticación y sesiones**: contraseñas con hash (Werkzeug), bloqueo
   de cuenta tras 5 intentos fallidos por 5 minutos.
3. **Control de acceso y manejo de errores**: control de acceso basado en rol (403
   ante escalada de privilegios) y páginas de error genéricas sin stack traces
   (DEBUG=False).
4. **Registro de auditoría**: todos los eventos de seguridad (logins fallidos,
   bloqueos, accesos denegados, entradas rechazadas) quedan en `security_audit.log`.

## Pruebas de penetración (pentesting funcional)

Con el servidor corriendo, ejecutar en otra terminal:

```bash
python3 pentest.py
```

El script ataca la instancia real con 11 casos (XSS, RUT adulterado, montos
maliciosos, inyección tipo SQL, carga de webshell, fuerza bruta de login,
escalada de privilegios, y errores con IDs fuera de rango) y reporta si cada
uno fue bloqueado exitosamente por los controles implementados.

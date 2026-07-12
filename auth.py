from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime

from database import (
    obtener_conexion,
    buscar_usuario,
)

ph = PasswordHasher()

MAX_INTENTOS = 5


# =====================================================
# REGISTRAR USUARIO
# =====================================================

def registrar_usuario(usuario, password, rol="Empleado"):

    if not usuario.strip():
        return False, "Debe ingresar un usuario."

    if not password:
        return False, "Debe ingresar una contraseña."

    if buscar_usuario(usuario):
        return False, "El usuario ya existe."

    password_hash = ph.hash(password)

    with obtener_conexion() as conn:

        conn.execute("""
            INSERT INTO usuarios
            (
                usuario,
                password_hash,
                rol,
                estado,
                intentos_fallidos
            )
            VALUES
            (?, ?, ?, 'Activa', 0)
        """,
        (
            usuario,
            password_hash,
            rol
        ))

        conn.commit()

    return True, "Usuario registrado correctamente."


# =====================================================
# LOGIN
# =====================================================

def iniciar_sesion(usuario, password):

    datos = buscar_usuario(usuario)

    if datos is None:
        return False, "El usuario no existe."

    if datos["estado"] == "Bloqueada":
        return False, "La cuenta está bloqueada."

    try:

        ph.verify(
            datos["password_hash"],
            password
        )

        with obtener_conexion() as conn:

            conn.execute("""
                UPDATE usuarios
                SET
                    intentos_fallidos = 0,
                    ultimo_acceso = ?
                WHERE usuario = ?
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                usuario
            ))

            conn.commit()

        return True, datos["rol"]

    except VerifyMismatchError:

        intentos = datos["intentos_fallidos"] + 1

        estado = "Activa"

        if intentos >= MAX_INTENTOS:
            estado = "Bloqueada"

        with obtener_conexion() as conn:

            conn.execute("""
                UPDATE usuarios
                SET
                    intentos_fallidos = ?,
                    estado = ?
                WHERE usuario = ?
            """,
            (
                intentos,
                estado,
                usuario
            ))

            conn.commit()

        restantes = MAX_INTENTOS - intentos

        if restantes > 0:
            return False, f"Contraseña incorrecta. Intentos restantes: {restantes}"

        return False, "Cuenta bloqueada por demasiados intentos."


# =====================================================
# BLOQUEAR
# =====================================================

def bloquear_usuario(usuario):

    with obtener_conexion() as conn:

        conn.execute("""
            UPDATE usuarios
            SET estado='Bloqueada'
            WHERE usuario=?
        """,(usuario,))

        conn.commit()


# =====================================================
# DESBLOQUEAR
# =====================================================

def desbloquear_usuario(usuario):

    with obtener_conexion() as conn:

        conn.execute("""
            UPDATE usuarios
            SET
                estado='Activa',
                intentos_fallidos=0
            WHERE usuario=?
        """,(usuario,))

        conn.commit()


# =====================================================
# CAMBIAR ROL
# =====================================================

def cambiar_rol(usuario, rol):

    with obtener_conexion() as conn:

        conn.execute("""
            UPDATE usuarios
            SET rol=?
            WHERE usuario=?
        """,
        (
            rol,
            usuario
        ))

        conn.commit()
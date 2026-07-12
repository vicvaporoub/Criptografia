'''
Esquema de BD - 4 tablas clave:

- usuarios: Almacena las identidades, los hashes de contraseñas y el estado de bloqueo.
- llaves_publicas: Guarda las llaves asimétricas públicas asociadas a cada usuario. 
  Las llaves privadas no se guardan aquí (se las queda el cliente).
- paquetes_archivos: Contiene los metadatos de los archivos cifrados en tránsito 
  y los componentes necesarios para el descifrado (texto cifrado, nonces, tags y firmas).
- logs_auditoria: El registro histórico inmutable exigido por la rúbrica.
'''

import sqlite3
import json
import secrets
from datetime import datetime

DB_NAME = "seguridad.db"

def obtener_conexion():
    """Establece conexión con SQLite y activa soporte para llaves foráneas."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def inicializar_bd():
    """Crea la estructura física de la base de datos si no existe."""
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        
        # 1. TABLA DE USUARIOS
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            usuario TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('Superusuario', 'Empleado', 'Auditor')),
            estado TEXT NOT NULL DEFAULT 'Activa' CHECK(estado IN ('Activa', 'Bloqueada')),
            intentos_fallidos INTEGER DEFAULT 0,
            ultimo_acceso TEXT
        );
        """)
        
        # 2. TABLA DE LLAVES PÚBLICAS
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS llaves_publicas (
            usuario TEXT PRIMARY KEY,
            pub_x TEXT NOT NULL,  -- Llave pública para cifrado/acuerdo (X25519)
            pub_ed TEXT NOT NULL, -- Llave pública para firma digital (Ed25519)
            fecha_registro TEXT NOT NULL,
            FOREIGN KEY (usuario) REFERENCES usuarios(usuario) ON DELETE CASCADE
        );
        """)
        
        # 3. TABLA DE PAQUETES DE ARCHIVOS CIFRADOS
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS paquetes_archivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emisor TEXT NOT NULL,
            destinatario TEXT NOT NULL,
            archivo_nombre TEXT NOT NULL,
            texto_cifrado_hex TEXT NOT NULL,
            iv_hex TEXT NOT NULL,
            llave_efemera_pub TEXT NOT NULL,
            firma_digital_hex TEXT NOT NULL,
            nonce_protocolo TEXT UNIQUE NOT NULL, -- Evita Replay Attacks
            timestamp TEXT NOT NULL,
            FOREIGN KEY (emisor) REFERENCES usuarios(usuario),
            FOREIGN KEY (destinatario) REFERENCES usuarios(usuario)
        );
        """)
        
        # 4. TABLA DE LOGS DE AUDITORÍA
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs_auditoria (
            id TEXT PRIMARY KEY,
            fecha_hora TEXT NOT NULL,
            nivel TEXT NOT NULL CHECK(nivel IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
            evento TEXT NOT NULL,
            usuario TEXT,
            detalle TEXT NOT NULL
        );
        """)
        
        conn.commit()

# ============================================================================
# FUNCIONES DE GESTIÓN (API de la Base de Datos - Conectadas con app.py)
# ============================================================================

def registrar_log(nivel: str, evento: str, usuario: str, detalle: str):
    """Inserta de forma segura un evento en la bitácora generando un ID único automáticamente."""
    id_evento = secrets.token_hex(4)  # Satisface el ID requerido por tu esquema sin romper app.py
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with obtener_conexion() as conn:
        conn.execute("""
            INSERT INTO logs_auditoria (id, fecha_hora, nivel, evento, usuario, detalle)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (id_evento, ahora, nivel, evento, usuario, detalle))
        conn.commit()

def registrar_llaves_publicas(usuario: str, pem_pub_firma: bytes, pem_pub_cifrado: bytes):
    """Vincula y guarda las llaves públicas PEM del usuario en la base de datos."""
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Aseguramos que se guarden como texto legible en la BD
    pub_ed_str = pem_pub_firma.decode('utf-8') if isinstance(pem_pub_firma, bytes) else pem_pub_firma
    pub_x_str = pem_pub_cifrado.decode('utf-8') if isinstance(pem_pub_cifrado, bytes) else pem_pub_cifrado
    
    with obtener_conexion() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO llaves_publicas (usuario, pub_x, pub_ed, fecha_registro)
            VALUES (?, ?, ?, ?)
        """, (usuario, pub_x_str, pub_ed_str, ahora))
        conn.commit()

def obtener_llave_publica_cifrado(usuario: str) -> bytes:
    """Recupera la llave X25519 del destinatario para ejecutar el acuerdo de llaves."""
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT pub_x FROM llaves_publicas WHERE usuario = ?", (usuario,))
        row = cursor.fetchone()
        if row and row['pub_x']:
            return row['pub_x'].encode('utf-8')
        return b""

def obtener_llave_publica_firma(usuario: str) -> bytes:
    """Recupera la llave Ed25519 del emisor para verificar la firma de un archivo."""
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT pub_ed FROM llaves_publicas WHERE usuario = ?", (usuario,))
        row = cursor.fetchone()
        if row and row['pub_ed']:
            return row['pub_ed'].encode('utf-8')
        return b""

def guardar_paquete_archivo(emisor: str, destinatario: str, paquete_json: str) -> bool:
    """
    Desempaqueta el JSON enviado por app.py y mapea sus propiedades a las 
    columnas individuales de tu tabla de paquetes de forma limpia.
    """
    try:
        datos = json.loads(paquete_json)
        # Extraemos los campos buscando nombres estándar del criptosistema
        nombre = datos.get("nombre_archivo") or datos.get("nombre", "archivo.bin")
        texto_hex = datos.get("texto_cifrado_hex") or datos.get("contenido_cifrado", "")
        iv_hex = datos.get("iv_hex") or datos.get("nonce_aes", "")
        llave_pub_efemera = datos.get("llave_efemera_pub") or datos.get("llave_publica_efemera") or ""
        firma_hex = datos.get("firma_digital_hex") or datos.get("firma", "")
        nonce = datos.get("nonce_protocolo") or datos.get("nonce", "")
        timestamp = datos.get("timestamp") or datetime.now().isoformat()
        
        with obtener_conexion() as conn:
            conn.execute("""
                INSERT INTO paquetes_archivos 
                (emisor, destinatario, archivo_nombre, texto_cifrado_hex, iv_hex, llave_efemera_pub, firma_digital_hex, nonce_protocolo, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (emisor, destinatario, nombre, texto_hex, iv_hex, llave_pub_efemera, firma_hex, nonce, timestamp))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Si salta esta excepción es porque el nonce_protocolo violó la regla UNIQUE (Ataque de repetición)
        return False

def obtener_paquetes_recibidos(usuario: str) -> list:
    """
    Busca los paquetes destinados al usuario y reconstruye dinámicamente el JSON 
    para que la interfaz de descifrado en app.py lo procese sin alterar tu esquema relacional.
    """
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT emisor, archivo_nombre, texto_cifrado_hex, iv_hex, llave_efemera_pub, firma_digital_hex, nonce_protocolo, timestamp 
            FROM paquetes_archivos 
            WHERE destinatario = ?
        """, (usuario,))
        rows = cursor.fetchall()
        
        resultado = []
        for row in rows:
            paquete_dict = {
                "nombre_archivo": row["archivo_nombre"],
                "texto_cifrado_hex": row["texto_cifrado_hex"],
                "iv_hex": row["iv_hex"],
                "llave_efemera_pub": row["llave_efemera_pub"],
                "firma_digital_hex": row["firma_digital_hex"],
                "nonce_protocolo": row["nonce_protocolo"],
                "timestamp": row["timestamp"]
            }
            resultado.append({
                "remitente": row["emisor"],
                "paquete_json": json.dumps(paquete_dict)
            })
        return resultado

def obtener_logs():
    """Recupera todos los logs para la vista de administración."""
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT fecha_hora AS [Fecha y hora], nivel AS Nivel, evento AS Evento, usuario AS Usuario, detalle AS Detalle, id AS [ID evento] FROM logs_auditoria ORDER BY fecha_hora DESC")
        return [dict(row) for row in cursor.fetchall()]

def obtener_usuarios():
    """Recupera los usuarios registrados para el panel."""
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT usuario AS Usuario, rol AS Rol, estado AS Estado, ultimo_acceso AS [Último acceso] FROM usuarios")
        return [dict(row) for row in cursor.fetchall()]
    
def buscar_usuario(usuario):
    with obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT *
            FROM usuarios
            WHERE usuario=?
        """,(usuario,))
        return cursor.fetchone()
    
def cambiar_rol(usuario, nuevo_rol):
    with obtener_conexion() as conn:
        conn.execute("""
            UPDATE usuarios
            SET rol=?
            WHERE usuario=?
        """, (nuevo_rol, usuario))
        conn.commit()

def eliminar_usuario(usuario):
    with obtener_conexion() as conn:
        conn.execute("""
            DELETE
            FROM usuarios
            WHERE usuario=?
        """,(usuario,))
        conn.commit()
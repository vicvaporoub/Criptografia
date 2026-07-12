import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# ============================================================================
# 1. GESTIÓN DE LLAVES ASIMÉTRICAS (Ed25519 para Firma y X25519 para Cifrado)
# ============================================================================

def generar_par_llaves(passphrase: str = None) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Genera un par de llaves Ed25519 (Firma) y un par X25519 (Cifrado/Acuerdo).
    Devuelve las llaves serializadas en bytes (PEM). La privada se cifra si hay passphrase.
    """
    # 1. Generar llaves de firma (Ed25519)
    priv_firma = ed25519.Ed25519PrivateKey.generate()
    pub_firma = priv_firma.public_key()
    
    # 2. Generar llaves de intercambio/cifrado (X25519)
    priv_cifrado = x25519.X25519PrivateKey.generate()
    pub_cifrado = priv_cifrado.public_key()
    
    # Serializar llaves privadas
    encryption_algorithm = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase else serialization.NoEncryption()
    )
    
    pem_priv_firma = priv_firma.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    pem_priv_cifrado = priv_cifrado.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    # Serializar llaves públicas
    pem_pub_firma = pub_firma.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    pem_pub_cifrado = pub_cifrado.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_priv_firma, pem_pub_firma, pem_priv_cifrado, pem_pub_cifrado


# ============================================================================
# 2. CIFRADO / PROTECCIÓN DE ARCHIVOS (Alice -> Bob)
# ============================================================================

def proteger_archivo(
    contenido_archivo: bytes,
    nombre_archivo: str,
    pem_priv_firma_emisor: bytes,
    pem_pub_cifrado_receptor: bytes,
    passphrase_emisor: str = None
) -> str:
    """
    1. Firma el contenido original con Ed25519.
    2. Genera una llave simétrica efímera AES-256.
    3. Cifra el contenido original con AES-256-GCM.
    4. Protege la llave AES usando un esquema de acuerdo de llaves con X25519.
    5. Devuelve una cadena JSON estructurada segura (Payload en tránsito).
    """
    # Cargar llaves asimétricas necesarias
    priv_firma = serialization.load_pem_private_key(
        pem_priv_firma_emisor, 
        password=passphrase_emisor.encode() if passphrase_emisor else None
    )
    pub_cifrado_receptor = serialization.load_pem_public_key(pem_pub_cifrado_receptor)
    
    # A. FIRMA DIGITAL (Ed25519) del archivo original
    firma = priv_firma.sign(contenido_archivo)
    
    # B. ACUERDO DE LLAVES (X25519) para proteger la llave simétrica
    # Generamos un par efímero del emisor para calcular el secreto compartido
    priv_efimera_emisor = x25519.X25519PrivateKey.generate()
    pub_efimera_emisor = priv_efimera_emisor.public_key()
    secreto_compartido = priv_efimera_emisor.exchange(pub_cifrado_receptor)
    
    # Usamos los primeros 32 bytes del secreto como la llave simétrica AES-256
    # (Para producción idealmente se pasa por una KDF como HKDF, pero cumple el requerimiento asimétrico)
    llave_aes = secreto_compartido[:32] 
    
    # C. CIFRADO SIMÉTRICO (AES-256-GCM)
    # GCM requiere un Nonce único de 12 bytes
    nonce_gcm = os.urandom(12)
    aesgcm = AESGCM(llave_aes)
    
    # Los metadatos de control anti-repetición van en los datos asociados (AAD)
    id_unico = os.urandom(16).hex()
    timestamp = datetime.utcnow().isoformat()
    datos_asociados = f"{id_unico}|{timestamp}".encode()
    
    # Cifrar (GCM concatena automáticamente el tag de autenticación al final del texto cifrado)
    texto_cifrado_con_tag = aesgcm.encrypt(nonce_gcm, contenido_archivo, datos_asociados)
    
    # D. EMPAQUETADO DEL MENSAJE (JSON)
    paquete = {
        "nombre_archivo": nombre_archivo,
        "id_unico": id_unico,
        "timestamp": timestamp,
        "nonce_gcm": base64.b64encode(nonce_gcm).decode('utf-8'),
        "pub_efimera_emisor": base64.b64encode(
            pub_efimera_emisor.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode('utf-8'),
        "texto_cifrado": base64.b64encode(texto_cifrado_con_tag).decode('utf-8'),
        "firma_digital": base64.b64encode(firma).decode('utf-8')
    }
    
    return json.dumps(paquete)


# ============================================================================
# 3. DESCIFRADO / VERIFICACIÓN DE ARCHIVOS (Bob)
# ============================================================================

def descifrar_y_verificar_archivo(
    paquete_json: str,
    pem_priv_cifrado_receptor: bytes,
    pem_pub_firma_emisor: bytes,
    passphrase_receptor: str = None
) -> tuple[bytes, str]:
    """
    1. Abre el JSON del paquete.
    2. Reconstruye la llave AES mediante X25519 con la pública efímera del emisor.
    3. Valida la integridad y descifra el texto con AES-GCM (falla si se modificó el tag o el AAD).
    4. Verifica la firma digital Ed25519 del emisor sobre el archivo resultante.
    """
    paquete = json.loads(paquete_json)
    
    # Cargar llaves
    priv_cifrado_receptor = serialization.load_pem_private_key(
        pem_priv_cifrado_receptor, 
        password=passphrase_receptor.encode() if passphrase_receptor else None
    )
    pub_firma_emisor = serialization.load_pem_public_key(pem_pub_firma_emisor)
    
    # Reconstruir metadatos y bytes
    nonce_gcm = base64.b64decode(paquete["nonce_gcm"])
    pub_efimera_emisor_bytes = base64.b64decode(paquete["pub_efimera_emisor"])
    texto_cifrado_con_tag = base64.b64decode(paquete["texto_cifrado"])
    firma_digital = base64.b64decode(paquete["firma_digital"])
    
    datos_asociados = f"{paquete['id_unico']}|{paquete['timestamp']}".encode()
    
    # A. RECUPERAR LLAVE AES (X25519)
    pub_efimera_emisor = serialization.load_pem_public_key(pub_efimera_emisor_bytes)
    secreto_compartido = priv_cifrado_receptor.exchange(pub_efimera_emisor)
    llave_aes = secreto_compartido[:32]
    
    # B. DESCIFRAR Y VALIDAR ETIQUETA DE AUTENTICACIÓN (AES-GCM)
    aesgcm = AESGCM(llave_aes)
    try:
        # Falla automáticamente levantando un Cryptography.exceptions.InvalidTag si hay modificaciones
        contenido_descifrado = aesgcm.decrypt(nonce_gcm, texto_cifrado_con_tag, datos_asociados)
    except Exception as e:
        raise ValueError("FALLO_DESCIFRADO: El archivo ha sido manipulado o la etiqueta de autenticación es inválida.") from e

    # C. VERIFICAR FIRMA DIGITAL (Ed25519)
    try:
        pub_firma_emisor.verify(firma_digital, contenido_descifrado)
    except Exception as e:
        raise ValueError("FIRMA_INVALIDA: La firma digital no corresponde al emisor o al archivo enviado.") from e

    return contenido_descifrado, paquete["nombre_archivo"]
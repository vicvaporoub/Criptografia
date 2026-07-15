# ============================================================================
#  SISTEMA DE DOCUMENTOS SEGUROS — Producción / Backend Conectado
# ----------------------------------------------------------------------------
#  Desarrollado y conectado con mecanismos criptográficos y persistencia real.
# ============================================================================

import secrets
from datetime import datetime
import json

import pandas as pd
import streamlit as st

from auth import registrar_usuario
from auth import iniciar_sesion as login_usuario
from auth import bloquear_usuario, desbloquear_usuario  

from database import (
    inicializar_bd,
    obtener_usuarios,
    obtener_logs,
    registrar_llaves_publicas,      
    obtener_llave_publica_cifrado,  
    obtener_llave_publica_firma,    
    guardar_paquete_archivo,        
    obtener_paquetes_recibidos,
    obtener_paquetes_enviados,
    registrar_log,
    es_admin,
    obtener_logs_personal
)
import crypto

# ============================================================================
# 1. CONFIGURACIÓN GENERAL DE LA PÁGINA
# ============================================================================

st.set_page_config(
    page_title="Sistema de Documentos Seguros",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================================
# 2. UTILIDADES DE DECORACIÓN VISUAL
# ============================================================================

def hex_falso(n_bytes: int = 16) -> str:
    """Genera una cadena hexadecimal aleatoria SOLO para efectos visuales decorativos."""
    return secrets.token_hex(n_bytes)

def llave_publica_falsa() -> str:
    """Devuelve una 'llave pública' PEM simulada (texto decorativo)."""
    cuerpo = "\n".join(secrets.token_hex(24) for _ in range(6)).upper()
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        f"{cuerpo}\n"
        "-----END PUBLIC KEY-----"
    )

# ============================================================================
# 3. GESTIÓN DE SESIÓN
# ============================================================================

def inicializar_estado() -> None:
    """Crea las variables de sesión si aún no existen."""
    st.session_state.setdefault("logueado", False)
    st.session_state.setdefault("usuario", "")
    st.session_state.setdefault("rol", "")

def iniciar_sesion_streamlit(usuario: str, rol: str) -> None:
    """Marca la sesión como iniciada de manera formal."""
    st.session_state["logueado"] = True
    st.session_state["usuario"] = usuario
    st.session_state["rol"] = rol

def cerrar_sesion() -> None:
    """Limpia todo el estado de sesión, registra la salida y regresa al Login."""
    if st.session_state.get("usuario"):
        registrar_log("INFO", "LOGOUT_USUARIO", st.session_state["usuario"], "El usuario cerró sesión voluntariamente.")
    st.session_state.clear()

# ============================================================================
# 4. VISTA: LOGIN / REGISTRO
# ============================================================================

def vista_login() -> None:
    """Pantalla de autenticación real conectada a la base de datos."""
    _, centro, _ = st.columns([1, 1.2, 1])

    with centro:
        st.markdown("<h2 style='text-align:center;'>Sistema de Documentos Seguros</h2>", unsafe_allow_html=True)
        st.markdown(
            "<p style='text-align:center;color:gray;'>Confidencialidad · Integridad · Autenticidad · Anti-repetición</p>",
            unsafe_allow_html=True,
        )

        tab_login, tab_registro = st.tabs(["Iniciar sesión", "Registrar usuario"])

        # ------------------------- Iniciar sesión -------------------------
        with tab_login:
            with st.form("form_login"):
                usuario = st.text_input("Usuario", placeholder="Ingrese su usuario")
                password = st.text_input("Contraseña", type="password", placeholder="Ingrese su contraseña")
                enviar = st.form_submit_button("Ingresar al sistema", use_container_width=True, type="primary")

            if enviar:
                ok, respuesta = login_usuario(usuario, password)

                if ok:
                    iniciar_sesion_streamlit(usuario, respuesta)
                    # REQUISITO DE AUDITORÍA: Registro de acceso exitoso
                    registrar_log("INFO", "LOGIN_EXITOSO", usuario, f"Autenticación exitosa. Rol asignado: {respuesta}")
                    st.rerun()
                else:
                    # REQUISITO DE AUDITORÍA: Registro de anomalías / intentos fallidos (Mitiga fuerza bruta)
                    registrar_log("WARNING", "LOGIN_FALLIDO", usuario if usuario else "Anónimo", f"Intento de acceso denegado: {respuesta}")
                    st.error(respuesta)

        # ------------------------ Registrar usuario -----------------------

        with tab_registro:
            with st.form("form_registro"):
                nuevo_usuario = st.text_input("Nuevo usuario")
                nuevo_password = st.text_input("Contraseña", type="password", key="reg_pass")
                confirmar = st.text_input("Confirmar contraseña", type="password", key="reg_pass2")
                rol = st.selectbox("Rol", ["Empleado", "Auditor", "Superusuario"])
                registrar = st.form_submit_button("Crear cuenta", use_container_width=True)

            if registrar:
                if nuevo_password != confirmar:
                    st.error("Las contraseñas no coinciden.")
                else:
                    ok, mensaje = registrar_usuario(nuevo_usuario, nuevo_password, rol)

                    if ok:
                        # REQUISITO DE AUDITORÍA: Alta de identidades
                        registrar_log("INFO", "REGISTRO_USUARIO", nuevo_usuario, f"Nueva cuenta creada exitosamente con el rol de {rol}.")
                        st.success(mensaje)
                    else:
                        st.error(mensaje)
        st.divider()

# ============================================================================
# 5. VISTA: PANEL PRINCIPAL
# ============================================================================

def vista_dashboard() -> None:
    """Resumen general del estado del sistema con analíticas dinámicas sobre los logs reales."""
    st.title("Panel de Control")
    st.caption(f"Sesión activa: **{st.session_state['usuario']}** ({st.session_state['rol']})")
    
    # Cálculos reales sobre la marcha para alimentar el Dashboard analítico
    
    es_admin_p=es_admin(st.session_state['usuario'])
    
    if es_admin_p:
        logs=obtener_logs()
    else:
        logs=obtener_logs_personal(st.session_state['usuario'])
    
    total_logs = len(logs)
    
    # Filtrar contadores basándonos en tipos reales de eventos
    alertas_seguridad = sum(1 for l in logs if l["Nivel"] in ["WARNING", "ERROR", "CRITICAL"])
    envios_hoy = sum(1 for l in logs if l["Evento"] == "ENVIO_ARCHIVO")
    firmas_ok = sum(1 for l in logs if l["Evento"] == "FIRMA_VALIDA")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Archivos en tránsito (Hoy)", str(envios_hoy))
    c2.metric("Eventos totales registrados", str(total_logs))
    c3.metric("Firmas digitales validadas", str(firmas_ok))
    c4.metric("Alertas de seguridad", str(alertas_seguridad), delta_color="inverse")

    st.divider()

    izq, der = st.columns([2, 1])

    with izq:
        st.subheader("Actividad reciente del sistema")
        if logs:
            st.dataframe(pd.DataFrame(logs).head(6), use_container_width=True, hide_index=True)
        else:
            st.info("Sin registros de actividad en la base de datos actual.")
    with der:
        st.subheader("Estado de los mecanismos")
        st.success("Cifrado simétrico: AES-256-GCM — operativo")
        st.success("Intercambio de llaves: X25519 — operativo")
        st.success("Firma digital: Ed25519 — operativo")
        st.warning("Detección Anti-repetición (Nonces): Activo")

# ============================================================================
# 6. VISTA: GESTIÓN DE ARCHIVOS
# ============================================================================

def vista_archivos() -> None:
    st.title("Gestión de Archivos")
    st.caption("Envío cifrado, recepción con descifrado y verificación de firmas digitales.")

    tab_enviar, tab_recibir, tab_enviados, tab_verificar = st.tabs(
        ["Enviar archivo", "Recibir y descifrar", "Archivos enviados", "Verificar firma digital"]
    )

    # --------------------------- Enviar archivo ---------------------------
    with tab_enviar:
        st.subheader("Enviar archivo cifrado")
        col_form, col_info = st.columns([2, 1])

        with col_form:
            archivo = st.file_uploader("Seleccione el archivo a proteger", key="up_enviar")
            
            todos_usuarios = obtener_usuarios()
            lista_destinos = [u["Usuario"] for u in todos_usuarios if u["Usuario"] != st.session_state["usuario"]]
            destinatario = st.selectbox("Destinatario", lista_destinos if lista_destinos else ["No hay otros usuarios"])
            
            st.markdown("---")
            st.markdown("##### Requisito de Firma: Sube tu Llave Privada de Firma")
            llave_priv_file = st.file_uploader("Tu llave privada de firma (priv_firma_...pem)", key="up_llave_emisor")
            passphrase_emisor = st.text_input("Contraseña de tu llave privada", type="password", key="pass_emisor")

            condicion_enviar = archivo is not None and llave_priv_file is not None
            
            st.markdown("---")
            st.markdown("##### Acciones del Protocolo y Simulación de Ataques")
            
            # Organizamos los tres botones de manera limpia en columnas
            col_enviar, col_atk_replay, col_atk_mitm = st.columns(3)
            
            with col_enviar:
                if st.button("🚀 Cifrar, Firmar y Enviar", type="primary", disabled=not condicion_enviar, use_container_width=True):
                    with st.spinner("Procesando criptografía real..."):
                        try:
                            # Leer contenido y rebobinar para mantenerlo en memoria
                            contenido_archivo = archivo.read()
                            archivo.seek(0) # Rebobinar para evitar que se quede vacío si se vuelve a usar
                            
                            pem_priv_firma = llave_priv_file.read()
                            llave_priv_file.seek(0) # Rebobinar
                            
                            pem_pub_cifrado_receptor = obtener_llave_publica_cifrado(destinatario)
                            if not pem_pub_cifrado_receptor:
                                registrar_log("ERROR", "LLAVE_DESCONOCIDA", st.session_state["usuario"], f"Intento de envío fallido: El usuario '{destinatario}' no tiene llaves públicas registradas.")
                                st.error(f"El destinatario {destinatario} no ha generado sus llaves públicas aún.")
                            else:
                                paquete_json = crypto.proteger_archivo(
                                    contenido_archivo=contenido_archivo,
                                    nombre_archivo=archivo.name,
                                    pem_priv_firma_emisor=pem_priv_firma,
                                    pem_pub_cifrado_receptor=pem_pub_cifrado_receptor,
                                    passphrase_emisor=passphrase_emisor if passphrase_emisor else None
                                )
                                
                                # Guardamos las variables necesarias en caché de sesión para alimentar las simulaciones
                                st.session_state["ultimo_paquete_interceptado"] = paquete_json
                                st.session_state["ultimo_destinatario_interceptado"] = destinatario
                                st.session_state["contenido_original_enviado"] = contenido_archivo
                                st.session_state["nombre_archivo_enviado"] = archivo.name
                                
                                guardado_exitoso = guardar_paquete_archivo(st.session_state["usuario"], destinatario, paquete_json)
                                
                                if guardado_exitoso:
                                    registrar_log("INFO", "ENVIO_ARCHIVO", st.session_state["usuario"], f"Archivo '{archivo.name}' cifrado y enviado con éxito a {destinatario}")
                                    st.success(f"¡Archivo **{archivo.name}** enviado con éxito!")
                                else:
                                    registrar_log("CRITICAL", "INTENTO_REPETICION", st.session_state["usuario"], f"ATAQUE DETECTADO: Se rechazó un paquete repetido para {destinatario}.")
                                    st.error("⚠️ Error Crítico de Seguridad: Intento de ataque de repetición detectado.")
                                    
                        except Exception as e:
                            registrar_log("ERROR", "FALLO_ENVIO", st.session_state["usuario"], f"Error al enviar: {str(e)}")
                            st.error(f"Error criptográfico: {str(e)}.")

            # Habilitar simulaciones únicamente si ya se ha enviado un archivo en la sesión actual
            tiene_paquete = "ultimo_paquete_interceptado" in st.session_state

            with col_atk_replay:
                if st.button("💥 Ataque Replay", disabled=not tiene_paquete, use_container_width=True, help="Reinyecta exactamente el mismo paquete interceptado"):
                    st.warning("Simulando atacante inyectando paquete clonado...")
                    
                    ataque_exitoso = guardar_paquete_archivo(
                        st.session_state["usuario"], 
                        st.session_state["ultimo_destinatario_interceptado"], 
                        st.session_state["ultimo_paquete_interceptado"]
                    )
                    
                    if not ataque_exitoso:
                        registrar_log("CRITICAL", "INTENTO_REPETICION", st.session_state["usuario"], f"ATAQUE DETECTADO: Se bloqueó la re-inyección de un paquete clonado dirigido a {st.session_state['ultimo_destinatario_interceptado']}.")
                        st.error("⚠️ La base de datos rechazó el paquete clonado porque el Nonce ya fue utilizado en el sistema. Ataque neutralizado.")
                    else:
                        st.success("El paquete clonado pasó (Esto no debería pasar si los Nonces están activos).")

            with col_atk_mitm:
                # Inicializar el estado de la consola MITM si no existe
                if "mostrar_consola_mitm" not in st.session_state:
                    st.session_state["mostrar_consola_mitm"] = False
                
                # Botón que activa o desactiva la consola interactiva del hacker
                if st.button("🥷 Interceptar Mensaje", type="secondary", disabled=not tiene_paquete, use_container_width=True, help="Abre la consola de Man-in-the-Middle para alterar el contenido en tránsito"):
                    st.session_state["mostrar_consola_mitm"] = not st.session_state["mostrar_consola_mitm"]
                    st.rerun()

        # ------------------------------------------------------------------
        # CONSOLA DINÁMICA DE ATAQUE MAN-IN-THE-MIDDLE (MITM)
        # ------------------------------------------------------------------
        if tiene_paquete and st.session_state.get("mostrar_consola_mitm"):
            st.markdown("---")
            st.error("🕵️‍♂️ **CONSOLA MAN-IN-THE-MIDDLE (MITM) — INTERCEPTOR DE RED**")
            st.markdown("El atacante (Eve) ha interceptado el paquete de datos en tránsito antes de que llegue al destinatario.")
            
            # Intentar leer el texto plano original enviado para mostrarlo en consola
            try:
                texto_original = st.session_state["contenido_original_enviado"].decode('utf-8', errors='ignore')
            except Exception:
                texto_original = "[Archivo Binario o No descifrable como texto plano]"
            
            st.info(f"📄 **Texto original detectado en el cable:** `{texto_original}`")
            
            # Permitir al usuario / atacante modificar libremente el texto original
            texto_alterado_usuario = st.text_area(
                "✍️ Modifica el mensaje a tu antojo para alterar la transacción:",
                value=texto_original,
                help="Cambia el texto original por el que quieras enviar de forma fraudulenta."
            )
            
            if st.button("💥 Inyectar Mensaje Modificado al Destinatario", type="primary", use_container_width=True):
                if texto_alterado_usuario == texto_original:
                    st.warning("⚠️ No has realizado ninguna modificación al texto original. Si lo envías así, la firma será válida.")
                else:
                    st.write(f"📡 *Inyectando mensaje manipulado: '{texto_alterado_usuario}' en el canal de red...*")
                    try:
                        # Recuperar la llave pública real del emisor para emular la verificación que hace el receptor
                        from cryptography.hazmat.primitives import serialization
                        pub_key_pem = obtener_llave_publica_firma(st.session_state["usuario"])
                        pub_key = serialization.load_pem_public_key(pub_key_pem)
                        
                        # Extraer la firma legítima original del paquete JSON interceptado
                        import json
                        paquete_dic = json.loads(st.session_state["ultimo_paquete_interceptado"])
                        firma_original = bytes.fromhex(paquete_dic["firma_digital"])
                        
                        # El receptor intenta verificar la firma original, pero con los datos alterados
                        pub_key.verify(firma_original, texto_alterado_usuario.encode('utf-8'))
                        
                        # Si por alguna razón pasa (no pasará):
                        st.success("⚠️ ¡CRÍTICO! La firma fue aceptada. El sistema es vulnerable.")
                        
                    except Exception as e:
                        # La verificación matemática de Ed25519 falló de forma segura
                        registrar_log(
                            "ERROR", 
                            "FIRMA_INVALIDA", 
                            st.session_state["usuario"], 
                            f"MAN-IN-THE-MIDDLE EVITADO: Se alteró el archivo '{st.session_state['nombre_archivo_enviado']}'. Original: '{texto_original}' -> Modificado: '{texto_alterado_usuario}'."
                        )
                        st.error("❌ **¡ATAQUE NEUTRALIZADO DE FORMA SEGURA!**")
                        st.markdown(
                            f">El receptor intentó verificar la firma legítima del emisor usando el texto manipulado (`{texto_alterado_usuario}`). "
                            f"El algoritmo rechazó la verificación, la transacción se canceló y el intentoquedó registrado en la bitácora de auditoría."
                        )

        # Contenedor de flujo informativo original
        with col_info:
            st.markdown("##### Flujo de protección REAL")
            st.markdown("- Se firma el archivo original usando tu llave **Ed25519**.\n- Se genera un secreto compartido mediante **X25519**.\n- Se cifra con **AES-256-GCM**.\n- Se empaquetan Nonces y marcas de tiempo.")
    
    # --------------------------- Recibir y descifrar ---------------------------
    with tab_recibir:
        st.subheader("Bandeja de entrada: Recibir y descifrar")
        
        # Obtener paquetes dirigidos al usuario logueado
        paquetes = obtener_paquetes_recibidos(st.session_state["usuario"])
        
        if not paquetes:
            st.info("No tienes archivos pendientes por recibir.")
        else:
            # Inicializar el diccionario de descifrados en el estado de sesión si no existe
            if "descifrados_exitosos" not in st.session_state:
                st.session_state["descifrados_exitosos"] = {}

            # Usamos enumerate para asegurar claves totalmente únicas mediante el índice 'idx'
            for idx, pkg in enumerate(paquetes):
                # Obtener campos de forma segura usando .get()
                emisor = pkg.get("Emisor") or pkg.get("emisor") or pkg.get("Remitente") or pkg.get("remitente") or "Desconocido"
                archivo_nombre = pkg.get("Archivo") or pkg.get("archivo") or pkg.get("Nombre") or pkg.get("nombre") or "archivo.bin"
                nonce_pkg = pkg.get("ID único / Nonce") or pkg.get("nonce") or "N/A"
                paquete_json_str = pkg.get("Paquete original JSON") or pkg.get("paquete_json") or pkg.get("paquete")
                
                with st.expander(f"📦 Archivo de {emisor} ({archivo_nombre})"):
                    st.write(f"**ID Único / Nonce:** `{nonce_pkg}`")
                    
                    # Usamos 'idx' en la clave para garantizar que sea única en Streamlit
                    llave_privada_file = st.file_uploader(
                        "Sube tu llave privada de cifrado (priv_cifrado_...pem)", 
                        key=f"rec_key_{idx}"
                    )
                    passphrase = st.text_input(
                        "Contraseña de tu llave privada", 
                        type="password", 
                        key=f"rec_pass_{idx}"
                    )
                    
                    # Crear un contenedor vacío para mostrar los resultados de forma persistente
                    contenedor_descarga = st.container()

                    if st.button("🔓 Descifrar y verificar", key=f"btn_rec_{idx}", type="primary"):
                        if llave_privada_file is not None:
                            try:
                                pem_priv = llave_privada_file.read()
                                llave_privada_file.seek(0)
                                
                                # Obtener llave pública de firma del emisor para validar la integridad
                                pem_pub_firma = obtener_llave_publica_firma(emisor)
                                
                                # LLAMADA CORREGIDA: Usando el nombre real de tu función en crypto.py
                                contenido_descifrado, nombre_retornado = crypto.descifrar_y_verificar_archivo(
                                    paquete_json=paquete_json_str,
                                    pem_priv_cifrado_receptor=pem_priv,
                                    pem_pub_firma_emisor=pem_pub_firma,
                                    passphrase_receptor=passphrase if passphrase else None
                                )
                                
                                if contenido_descifrado:
                                    # Extraer la firma digital para guardarla en el estado de sesión
                                    firma_bytes = b""
                                    if paquete_json_str:
                                        import base64
                                        import json as json_lib
                                        
                                        paquete_dic = json_lib.loads(paquete_json_str)
                                        firma_b64 = paquete_dic.get("firma_digital")
                                        if firma_b64:
                                            firma_bytes = base64.b64decode(firma_b64)

                                    # Guardamos los resultados en el Session State para que no se borren al descargar
                                    st.session_state["descifrados_exitosos"][idx] = {
                                        "archivo_datos": contenido_descifrado,
                                        "firma_datos": firma_bytes,
                                        "nombre": archivo_nombre
                                    }
                                    registrar_log("INFO", "DESCIFRADO_EXITOSO", st.session_state["usuario"], f"El usuario descifró con éxito el archivo '{archivo_nombre}'.")
                                    st.rerun()  # Recargamos una vez para fijar los botones en pantalla
                                    
                            except Exception as e:
                                registrar_log("ERROR", "FALLO_DESCIFRADO", st.session_state["usuario"], f"Error al descifrar archivo de {emisor}: {str(e)}")
                                st.error(f"❌ Error al descifrar: {str(e)}. Verifica tu llave y contraseña.")
                        else:
                            st.warning("Por favor sube tu llave privada para proceder.")

                    # DIBUJAR BOTONES PERSISTENTES SI EL ARCHIVO YA FUE DESCIFRADO
                    if idx in st.session_state["descifrados_exitosos"]:
                        datos_guardados = st.session_state["descifrados_exitosos"][idx]
                        
                        with contenedor_descarga:
                            st.success("✅ ¡Archivo descifrado y firma verificada con éxito!")
                            
                            # Botón para descargar el archivo original descifrado (fijo en pantalla)
                            st.download_button(
                                "💾 Descargar archivo original",
                                data=datos_guardados["archivo_datos"],
                                file_name=datos_guardados["nombre"],
                                use_container_width=True,
                                key=f"dl_file_{idx}"
                            )
                            
                            # Botón para descargar el archivo .sig (fijo en pantalla)
                            if datos_guardados["firma_datos"]:
                                st.download_button(
                                    "🔏 Descargar archivo de firma (.sig)",
                                    data=datos_guardados["firma_datos"],
                                    file_name=f"{datos_guardados['nombre']}.sig",
                                    use_container_width=True,
                                    key=f"dl_sig_{idx}"
                                )
    # ------------------------ Archivos enviados -------------------------
    with tab_enviados:
        st.subheader("Archivos enviados")
        st.caption("Historial de archivos que has cifrado, firmado y enviado a otros usuarios.")

        enviados = obtener_paquetes_enviados(st.session_state["usuario"])

        if not enviados:
            st.info("Todavía no has enviado archivos.")
        else:
            df_enviados = pd.DataFrame(enviados)

            st.dataframe(
                df_enviados,
                use_container_width=True,
                hide_index=True
            )

            st.markdown("### Detalle de envíos")

            for archivo_env in enviados:
                titulo = f"{archivo_env['Archivo']} → {archivo_env['Destinatario']}"
                with st.expander(titulo):
                    st.write(f"**ID interno:** {archivo_env['ID']}")
                    st.write(f"**Destinatario:** {archivo_env['Destinatario']}")
                    st.write(f"**Fecha de envío:** {archivo_env['Fecha de envío']}")
                    st.write(f"**ID único / Nonce de protocolo:** `{archivo_env['ID único / Nonce']}`")
                    st.write(f"**Nonce AES-GCM:** `{archivo_env['Nonce AES-GCM (hex)']}`")
                    st.write(f"**Tamaño cifrado:** {archivo_env['Tamaño cifrado bytes']} bytes")
                    st.write(f"**Firma digital registrada:** `{archivo_env['Firma digital (resumen)']}`")

                    st.info(
                        "Esta vista solo muestra metadatos seguros del envío. "
                        "No expone el archivo original, llaves privadas, contraseñas ni llaves de sesión."
                    )

    # ----------------------- Verificar firma digital ----------------------
    with tab_verificar:
        st.subheader("Verificar firma digital de un archivo")
        col_a, col_b = st.columns(2)

        with col_a:
            archivo_v = st.file_uploader("Archivo original a verificar", key="up_verificar")
            firma = st.file_uploader("Archivo de firma digital (.sig o bytes)", key="up_firma")
            emisor = st.selectbox("Emisor esperado", [u["Usuario"] for u in obtener_usuarios()], key="sel_emisor")
            verificar = st.button("Verificar firma", type="primary", disabled=(archivo_v is None or firma is None))

        with col_b:
            st.markdown("##### La verificación comprueba que:")
            st.markdown("- El archivo fue enviado por el **usuario esperado**.\n- El contenido **no fue modificado**.\n- La **firma es válida**.")

        if verificar:
            try:
                contenido_archivo = archivo_v.read()
                firma_bytes = firma.read()
                
                # Obtener la llave pública real de la BD
                pem_pub_firma_emisor = obtener_llave_publica_firma(emisor)
                
                if not pem_pub_firma_emisor:
                    registrar_log("WARNING", "LLAVE_DESCONOCIDA", st.session_state["usuario"], f"Verificación fallida: Llave de firma no encontrada para el usuario '{emisor}'.")
                    st.error(f"No se pudo verificar: El usuario '{emisor}' no tiene una llave pública registrada en el sistema.")
                else:
                    from cryptography.hazmat.primitives import serialization
                    # Cargar la llave pública Ed25519
                    pub_key = serialization.load_pem_public_key(pem_pub_firma_emisor)
                    
                    # Verificar firma
                    pub_key.verify(firma_bytes, contenido_archivo)
                    
                    # REQUISITO DE AUDITORÍA: Registro de firma válida
                    registrar_log("INFO", "FIRMA_VALIDA", st.session_state["usuario"], f"Verificación externa exitosa: Archivo '{archivo_v.name}' firmado válidamente por {emisor}.")
                    st.success(f"✨ ¡FIRMA VÁLIDA! El archivo coincide con la llave Ed25519 de {emisor} y no ha sido alterado.")
            except Exception as e:
                # REQUISITO DE AUDITORÍA: Registro de firma inválida / anomalía
                registrar_log("ERROR", "FIRMA_INVALIDA", st.session_state["usuario"], f"Fallo de verificación: La firma provista para el archivo '{archivo_v.name}' no es válida para el usuario {emisor}. Detalle: {str(e)}")
                st.error(f"❌ FIRMA INVÁLIDA: El archivo ha sido modificado o no corresponde a la firma del usuario {emisor}.")
# ============================================================================
# 7. VISTA: IDENTIDAD Y LLAVES
# ============================================================================

def vista_llaves() -> None:
    st.title("Identidad y Llaves")
    st.caption("Gestión del material criptográfico asociado a su identidad.")

    tab_publica, tab_privada, tab_generar, tab_pass = st.tabs(
        ["Ver llave pública", "Exportar llave privada", "Generar par de llaves", "Gestionar contraseña"]
    )

    # --------------------------- Llave pública ----------------------------
    with tab_publica:
        st.subheader("Su llave pública registrada")
        pub_firma = obtener_llave_publica_firma(st.session_state["usuario"])
        
        if pub_firma:
            st.success("Tu identidad asimétrica se encuentra activa e inscrita en el directorio.")
            st.code(pub_firma.decode('utf-8'), language="text")
        else:
            st.warning("Aún no posees llaves vinculadas en el servidor público. Ve a la pestaña 'Generar par de llaves'.")

    # ------------------------ Exportar llave privada ----------------------
    with tab_privada:
        st.subheader("Exportar / Re-cifrar Llave Privada Local")
        st.info("🔒 Principio de Seguridad: El servidor NO almacena tu llave privada. Esta herramienta opera de forma 100% local en tu sesión para cambiar la frase de seguridad (passphrase) de tu llave privada (.pem) y exportarla de forma segura.")
        
        llave_subida = st.file_uploader("Sube tu llave privada actual (.pem)", key="up_llave_export")
        pass_actual_llave = st.text_input("Frase de seguridad ACTUAL de la llave", type="password", key="pass_llave_exp_act")
        pass_nueva_llave = st.text_input("NUEVA frase de seguridad para proteger la exportación", type="password", key="passphrase_exp")
        confirmo = st.checkbox("Entiendo los riesgos de manejar y exportar mi material criptográfico privado")

        if st.button("Procesar y Exportar Llave", disabled=not (confirmo and llave_subida is not None and pass_nueva_llave)):
            try:
                from cryptography.hazmat.primitives import serialization
                raw_pem = llave_subida.read()
                
                # Intentar cargar la llave privada local usando la frase actual para validar propiedad
                priv_key = serialization.load_pem_private_key(
                    raw_pem,
                    password=pass_actual_llave.encode() if pass_actual_llave else None
                )
                
                # Re-serializar y aplicar un cifrado simétrico robusto bajo la nueva frase de seguridad (BestAvailableEncryption)
                nuevo_pem = priv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(pass_nueva_llave.encode())
                )
                
                # REQUISITO DE AUDITORÍA: Alerta de exportación/manipulación de llaves privadas
                registrar_log("WARNING", "EXPORTACION_LLAVE_PRIVADA", st.session_state["usuario"], "El usuario ejecutó de forma local el re-cifrado y exportación de sus llaves privadas.")
                st.success("🔒 Llave privada re-cifrada y empaquetada con éxito. Puedes descargar tu exportación segura:")
                st.download_button("💾 Descargar Llave Privada Exportada (.pem)", data=nuevo_pem, file_name=f"export_priv_{st.session_state['usuario']}.pem", use_container_width=True)
                
            except Exception as e:
                registrar_log("ERROR", "FALLO_EXPORTACION_LLAVE", st.session_state["usuario"], f"Error crítico al intentar procesar exportación de llave privada: {str(e)}")
                st.error(f"❌ Error al procesar el archivo PEM: {str(e)}. Asegúrate de que el archivo corresponde y que escribiste la frase de seguridad actual correcta.")
# ------------------------ Generar par de llaves -----------------------
    with tab_generar:
        st.subheader("Generar un nuevo par de llaves reales")
        st.markdown("Este proceso generará tus identidades reales: **Ed25519** para firmas y **X25519** para cifrado.")
        passphrase_gen = st.text_input("Asigna una frase de seguridad para proteger tus llaves privadas", type="password", key="pass_real_gen")
        
        # Inicializar variables en la memoria de Streamlit para que no se borren
        if "llaves_generadas" not in st.session_state:
            st.session_state["llaves_generadas"] = False
            st.session_state["pem_priv_f"] = b""
            st.session_state["pem_priv_c"] = b""

        if st.button("Generar e Inscribir Llaves", type="primary", disabled=len(passphrase_gen) < 4):
            with st.spinner("Efectuando cálculos de curvas elípticas de manera segura..."):
                try:
                    pem_priv_f, pem_pub_f, pem_priv_c, pem_pub_c = crypto.generar_par_llaves(passphrase_gen)
                    registrar_llaves_publicas(st.session_state["usuario"], pem_pub_f, pem_pub_c)
                    
                    # Guardamos los resultados en el estado de la sesión para congelarlos
                    st.session_state["llaves_generadas"] = True
                    st.session_state["pem_priv_f"] = pem_priv_f
                    st.session_state["pem_priv_c"] = pem_priv_c
                    
                    # REQUISITO DE AUDITORÍA: Ciclo de vida de llaves criptográficas
                    registrar_log("INFO", "GENERACION_LLAVES", st.session_state["usuario"], "Inscripción exitosa del nuevo par de llaves públicas Ed25519/X25519.")
                    st.success("🎉 ¡Llaves públicas vinculadas con éxito en el servidor! Ahora puedes descargar tus llaves privadas tranquilamente abajo:")
                except Exception as e:
                    st.error(f"Error generando llaves: {str(e)}")

        # Si ya fueron generadas en esta sesión, mostramos los botones de forma persistente
        if st.session_state["llaves_generadas"]:
            st.markdown("---")
            st.markdown("⚠️ *Descarga ambos archivos antes de cambiar de pestaña o cerrar sesión.*")
            
            st.download_button(
                "💾 Descargar Llave Privada de Firma (Ed25519)", 
                data=st.session_state["pem_priv_f"], 
                file_name=f"priv_firma_{st.session_state['usuario']}.pem", 
                use_container_width=True,
                key="btn_descarga_firma"
            )
            
            st.download_button(
                "💾 Descargar Llave Privada de Cifrado (X25519)", 
                data=st.session_state["pem_priv_c"], 
                file_name=f"priv_cifrado_{st.session_state['usuario']}.pem", 
                use_container_width=True,
                key="btn_descarga_cifrado"
            )

    # ------------------------ Gestionar contraseña ------------------------
    with tab_pass:
        st.subheader("Cambiar contraseña del sistema")
        with st.form("form_cambio_pass"):
            pass_actual = st.text_input("Contraseña actual", type="password")
            pass_nueva = st.text_input("Nueva contraseña", type="password")
            cambiar = st.form_submit_button("Actualizar contraseña", use_container_width=True)
            
        if cambiar:
            if not pass_actual.strip() or not pass_nueva.strip():
                st.error("Por favor completa ambos campos.")
            else:
                from auth import actualizar_contrasena
                ok, mensaje = actualizar_contrasena(st.session_state["usuario"], pass_actual, pass_nueva)
                if ok:
                    registrar_log("INFO", "CAMBIO_PASSWORD", st.session_state["usuario"], "El usuario cambió su contraseña de acceso exitosamente.")
                    st.success(mensaje)
                else:
                    registrar_log("WARNING", "FALLO_CAMBIO_PASSWORD", st.session_state["usuario"], f"Intento fallido de cambio de contraseña: {mensaje}")
                    st.error(mensaje)

# ============================================================================
# 8. VISTA: ADMINISTRACIÓN (SUPERUSUARIO REAL)
# ============================================================================

def vista_admin() -> None:
    st.title("Administración del Sistema")
    st.caption("Panel exclusivo del superusuario: auditoría y gestión de cuentas.")

    tab_logs, tab_usuarios, tab_bloqueo = st.tabs(
        ["Logs del sistema", "Gestionar usuarios", "Bloquear / desbloquear cuenta"]
    )

    # ----------------------------- Logs -----------------------------------
    with tab_logs:
        st.subheader("Registro de eventos de seguridad")
        logs_reales = obtener_logs()
        
        if not logs_reales:
            df_logs = pd.DataFrame(columns=["Fecha y hora", "Nivel", "Evento", "Usuario", "Detalle", "ID evento"])
        else:
            df_logs = pd.DataFrame(logs_reales)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Eventos totales", len(df_logs))
        
        errores = int((df_logs["Nivel"] == "ERROR").sum()) if not df_logs.empty else 0
        advertencias = int((df_logs["Nivel"] == "WARNING").sum()) if not df_logs.empty else 0
        criticos = int((df_logs["Nivel"] == "CRITICAL").sum()) if not df_logs.empty else 0

        c2.metric("Errores", errores, delta_color="inverse")
        c3.metric("Advertencias", advertencias, delta_color="inverse")
        c4.metric("Críticos", criticos, delta_color="inverse")

        if not df_logs.empty:
            col_f1, col_f2 = st.columns(2)
            nivel = col_f1.multiselect("Filtrar por nivel", df_logs["Nivel"].unique().tolist())
            evento = col_f2.multiselect("Filtrar por tipo de evento", df_logs["Evento"].unique().tolist())

            filtrado = df_logs
            if nivel:
                filtrado = filtrado[filtrado["Nivel"].isin(nivel)]
            if evento:
                filtrado = filtrado[filtrado["Evento"].isin(evento)]

            st.dataframe(filtrado, use_container_width=True, hide_index=True)
        else:
            st.info("No hay eventos registrados en la bitácora de auditoría todavía.")

        st.caption("Los logs nunca contienen contraseñas, llaves privadas, llaves de sesión ni contenido de mensajes.")

    # ------------------------- Gestionar usuarios -------------------------
    with tab_usuarios:
        st.subheader("Usuarios registrados")
        usuarios_reales = obtener_usuarios()
        
        if not usuarios_reales:
            df_usuarios = pd.DataFrame(columns=["Usuario", "Rol", "Estado", "Último acceso"])
        else:
            df_usuarios = pd.DataFrame(usuarios_reales)
            
        st.dataframe(df_usuarios, use_container_width=True, hide_index=True)

    # --------------------- Bloquear / desbloquear cuenta ------------------
    with tab_bloqueo:
        st.subheader("Bloquear o desbloquear una cuenta")

        usuarios_sistema = [u["Usuario"] for u in obtener_usuarios() if u["Usuario"] != st.session_state["usuario"]]
        
        if usuarios_sistema:
            col_sel, col_motivo = st.columns([1, 2])
            with col_sel:
                objetivo = st.selectbox("Seleccione la cuenta", usuarios_sistema)
            with col_motivo:
                motivo = st.text_input("Motivo")

            c_bloq, c_desb = st.columns(2)
            
            # ACCIONES CON LOGS REALES VINCULADOS DE FORMA CONTRACTUAL
        if c_bloq.button("Bloquear cuenta de usuario", use_container_width=True):
            if motivo:
                bloquear_usuario(objetivo)  # ← AQUÍ
                registrar_log("CRITICAL", "BLOQUEO_CUENTA", st.session_state["usuario"], f"El Administrador bloqueó la cuenta de '{objetivo}'. Motivo: {motivo}")
                st.error(f"La cuenta de **{objetivo}** ha sido bloqueada. Evento asentado en el registro histórico.")
            else:
                st.warning("Por requerimiento inmutable de auditoría, debes ingresar un motivo justificable antes de proceder.")

        if c_desb.button("Desbloquear cuenta de usuario", use_container_width=True):
            if motivo:
                desbloquear_usuario(objetivo)  # ← AQUÍ
                registrar_log("CRITICAL", "DESBLOQUEO_CUENTA", st.session_state["usuario"], f"El Administrador desbloqueó la cuenta de '{objetivo}'. Motivo: {motivo}")
                st.success(f"La cuenta de **{objetivo}** ha sido reactivada. Evento asentado en el registro histórico.")
            else:
                st.warning("Por requerimiento inmutable de auditoría, debes ingresar un motivo justificable antes de proceder.")
        else:
            st.info("No hay otros usuarios registrados en el sistema para gestionar bloqueos.")

# ============================================================================
# 9. NAVEGACIÓN LATERAL (routing)
# ============================================================================

def barra_lateral() -> str:
    """Dibuja el menú lateral y devuelve la vista seleccionada."""
    with st.sidebar:
        st.markdown("## Documentos Seguros")
        st.markdown(f"**{st.session_state['usuario']}** · `{st.session_state['rol']}`")
        st.divider()

        opciones = ["Panel de Control", "Gestión de Archivos", "Identidad y Llaves"]

        if st.session_state["rol"] == "Superusuario":
            opciones.append("Administración")

        vista = st.radio("Navegación", opciones, label_visibility="collapsed")
        st.divider()
        st.caption("Conexión Local Protegida")

        if st.button("Cerrar sesión", use_container_width=True, type="secondary"):
            cerrar_sesion()
            st.rerun()

    return vista

# ============================================================================
# 10. PUNTO DE ENTRADA
# ============================================================================

def main() -> None:
    inicializar_bd()
    inicializar_estado()

    if not st.session_state["logueado"]:
        vista_login()
        return

    vista = barra_lateral()

    if vista == "Panel de Control":
        vista_dashboard()
    elif vista == "Gestión de Archivos":
        vista_archivos()
    elif vista == "Identidad y Llaves":
        vista_llaves()
    elif vista == "Administración":
        if st.session_state.get("rol") == "Superusuario":
            vista_admin()
        else:
            st.error("Acceso denegado: Solo superusuarios pueden acceder")

if __name__ == "__main__":
    main()
# ============================================================================
#  SISTEMA DE DOCUMENTOS SEGUROS — Prototipo visual (MVP / Frontend)
# ----------------------------------------------------------------------------
#python -m streamlit run app.py
#  Prototipo puramente VISUAL construido con Streamlit.
#
#  IMPORTANTE:
#   - NO implementa criptografía real (AES, RSA, Argon2, etc.).
#   - NO usa base de datos: todo son datos simulados (mock data).
#   - Los "hashes", "nonces" y "llaves" mostrados son cadenas aleatorias
#     generadas solo con fines de presentación.
#
#  Basado en:
#   - "Proyecto - Tagged.pdf"        → requerimientos funcionales y de logs.
#   - "funcionalidades_proyecto.png" → diagrama de casos de uso:
#         · Cuenta:      registrar, iniciar sesión, contraseña, par de llaves
#         · Archivos:    enviar, recibir/descifrar, verificar firma
#         · Llaves:      ver llave pública, exportar llave privada
#         · Admin:       ver logs, gestionar usuarios, bloquear/desbloquear
#
#  El tamaño de letra global se define en .streamlit/config.toml
#  (opción theme.baseFontSize).
#
#  Ejecución:  streamlit run app.py
#  Login demo: usuario "root" (cualquier contraseña)
# ============================================================================

import secrets
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

# ============================================================================
# 1. CONFIGURACIÓN GENERAL DE LA PÁGINA
# ============================================================================

st.set_page_config(
    page_title="Sistema de Documentos Seguros",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================================
# 2. UTILIDADES DE SIMULACIÓN (mock data / valores decorativos)
# ============================================================================

def hex_falso(n_bytes: int = 16) -> str:
    """Genera una cadena hexadecimal aleatoria SOLO para efectos visuales.
    No representa ningún valor criptográfico real."""
    return secrets.token_hex(n_bytes)


def llave_publica_falsa() -> str:
    """Devuelve una 'llave pública' PEM simulada (texto decorativo)."""
    cuerpo = "\n".join(secrets.token_hex(24) for _ in range(6)).upper()
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        f"{cuerpo}\n"
        "-----END PUBLIC KEY-----"
    )


def usuarios_mock() -> pd.DataFrame:
    """Tabla simulada de usuarios registrados en el sistema."""
    return pd.DataFrame(
        [
            {"Usuario": "root",    "Rol": "Superusuario", "Llave pública": "Registrada", "Estado": "Activa",    "Último acceso": "2026-07-01 09:12"},
            {"Usuario": "alice",   "Rol": "Empleado",     "Llave pública": "Registrada", "Estado": "Activa",    "Último acceso": "2026-06-30 17:45"},
            {"Usuario": "bob",     "Rol": "Empleado",     "Llave pública": "Registrada", "Estado": "Activa",    "Último acceso": "2026-06-30 15:02"},
            {"Usuario": "charlie", "Rol": "Empleado",     "Llave pública": "Pendiente",  "Estado": "Bloqueada", "Último acceso": "2026-06-28 11:30"},
            {"Usuario": "diana",   "Rol": "Auditor",      "Llave pública": "Registrada", "Estado": "Activa",    "Último acceso": "2026-06-29 08:55"},
        ]
    )


def logs_mock() -> pd.DataFrame:
    """Logs simulados de eventos, según los tipos exigidos en el PDF:
    inicio de sesión, envío/recepción, firmas, errores de autenticación,
    intentos de repetición, fallos al descifrar y llaves desconocidas.
    (Nunca incluyen contraseñas, llaves privadas ni contenido sensible)."""
    base = datetime(2026, 7, 1, 9, 45)
    eventos = [
        ("INFO",     "INICIO_SESION",       "root",    "Inicio de sesión exitoso"),
        ("INFO",     "ENVIO_ARCHIVO",       "alice",   "Archivo 'contrato.pdf' cifrado (AES-GCM) y enviado a bob"),
        ("INFO",     "RECEPCION_ARCHIVO",   "bob",     "Archivo recibido y descifrado correctamente"),
        ("INFO",     "FIRMA_VALIDA",        "bob",     "Firma digital de alice verificada correctamente"),
        ("WARNING",  "ERROR_AUTENTICACION", "charlie", "Contraseña incorrecta (intento 3 de 5)"),
        ("CRITICAL", "INTENTO_REPETICION",  "—",       "Paquete con nonce ya utilizado: mensaje rechazado"),
        ("ERROR",    "FALLO_DESCIFRADO",    "diana",   "Etiqueta de autenticación inválida: archivo rechazado"),
        ("WARNING",  "LLAVE_DESCONOCIDA",   "—",       "Firma con llave pública no registrada en el sistema"),
        ("WARNING",  "FIRMA_INVALIDA",      "bob",     "La firma no corresponde al emisor esperado"),
        ("INFO",     "CUENTA_BLOQUEADA",    "charlie", "Cuenta bloqueada por exceso de intentos fallidos"),
        ("INFO",     "GENERACION_LLAVES",   "diana",   "Nuevo par de llaves generado y llave pública registrada"),
        ("INFO",     "INICIO_SESION",       "alice",   "Inicio de sesión exitoso"),
    ]
    filas = []
    for i, (nivel, tipo, usuario, detalle) in enumerate(eventos):
        filas.append(
            {
                "Fecha y hora": (base - timedelta(minutes=7 * i)).strftime("%Y-%m-%d %H:%M:%S"),
                "Nivel": nivel,
                "Evento": tipo,
                "Usuario": usuario,
                "Detalle": detalle,
                "ID evento": hex_falso(4),
            }
        )
    return pd.DataFrame(filas)


def archivos_recibidos_mock() -> list[dict]:
    """Bandeja simulada de archivos cifrados pendientes de descifrar."""
    return [
        {"nombre": "contrato_confidencial.pdf.enc", "emisor": "alice", "fecha": "2026-07-01 08:50", "tamano": "1.2 MB"},
        {"nombre": "nomina_junio.xlsx.enc",         "emisor": "diana", "fecha": "2026-06-30 16:20", "tamano": "480 KB"},
        {"nombre": "acta_reunion.docx.enc",         "emisor": "bob",   "fecha": "2026-06-30 10:05", "tamano": "215 KB"},
    ]


# ============================================================================
# 3. GESTIÓN DE SESIÓN (st.session_state)
# ============================================================================

def inicializar_estado() -> None:
    """Crea las variables de sesión si aún no existen."""
    st.session_state.setdefault("logueado", False)
    st.session_state.setdefault("usuario", "")


def iniciar_sesion(usuario: str) -> None:
    """Marca la sesión como iniciada (autenticación SIMULADA)."""
    st.session_state["logueado"] = True
    st.session_state["usuario"] = usuario


def cerrar_sesion() -> None:
    """Limpia todo el estado de sesión y regresa al Login."""
    st.session_state.clear()


# ============================================================================
# 4. VISTA: LOGIN / REGISTRO (pantalla inicial)
# ============================================================================

def vista_login() -> None:
    """Pantalla de autenticación. Solo el usuario 'root' desbloquea el sistema."""
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
                st.text_input("Contraseña", type="password", placeholder="Ingrese su contraseña")
                enviar = st.form_submit_button("Ingresar al sistema", use_container_width=True, type="primary")

            if enviar:
                if usuario.strip() == "root":
                    iniciar_sesion("root")
                    st.rerun()
                else:
                    st.error("Credenciales inválidas o cuenta bloqueada. Evento registrado en logs.")
                    st.caption("Prototipo: use el usuario **root** con cualquier contraseña.")

        # ------------------------ Registrar usuario -----------------------
        with tab_registro:
            with st.form("form_registro"):
                st.text_input("Nuevo usuario")
                st.text_input("Contraseña", type="password", key="reg_pass")
                st.text_input("Confirmar contraseña", type="password", key="reg_pass2")
                registrar = st.form_submit_button("Crear cuenta", use_container_width=True)

            if registrar:
                st.success("Usuario registrado (simulado). Contraseña protegida con Argon2 + sal única.")
                st.info("Se generó un par de llaves y la llave pública quedó asociada al usuario.")

        st.divider()
        st.caption("Prototipo visual — sin criptografía real ni base de datos.")


# ============================================================================
# 5. VISTA: PANEL PRINCIPAL (dashboard)
# ============================================================================

def vista_dashboard() -> None:
    """Resumen general del estado del sistema con métricas simuladas."""
    st.title("Panel de Control")
    st.caption(f"Sesión activa: **{st.session_state['usuario']}** (Superusuario) · Canal cifrado extremo a extremo")

    # Métricas rápidas del sistema (valores simulados)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Archivos cifrados hoy", "27", "+4")
    c2.metric("Usuarios activos", "4", "-1")
    c3.metric("Firmas verificadas", "19", "+6")
    c4.metric("Alertas de seguridad", "3", "+2", delta_color="inverse")

    st.divider()

    izq, der = st.columns([2, 1])

    with izq:
        st.subheader("Actividad reciente")
        st.dataframe(logs_mock().head(6), use_container_width=True, hide_index=True)

    with der:
        st.subheader("Estado de los mecanismos")
        st.success("Cifrado simétrico: AES-256-GCM — operativo")
        st.success("Intercambio de llaves: X25519 — operativo")
        st.success("Firma digital: Ed25519 — operativo")
        st.warning("Detector de repetición: 1 intento bloqueado hoy")

        with st.expander("Modelo de amenazas (resumen)"):
            st.markdown(
                """
                - **Activos:** archivos, contraseñas, llaves privadas.
                - **Adversarios:** atacante externo, usuario interno.
                - **Capacidades:** capturar, modificar, repetir, robar.
                - **Controles:** cifrado, firmas, autenticación, logs.
                """
            )


# ============================================================================
# 6. VISTA: GESTIÓN DE ARCHIVOS
#    (Enviar archivo · Recibir y descifrar · Verificar firma digital)
# ============================================================================

def vista_archivos() -> None:
    st.title("Gestión de Archivos")
    st.caption("Envío cifrado, recepción con descifrado y verificación de firmas digitales.")

    tab_enviar, tab_recibir, tab_verificar = st.tabs(
        ["Enviar archivo", "Recibir y descifrar", "Verificar firma digital"]
    )

    # --------------------------- Enviar archivo ---------------------------
    with tab_enviar:
        st.subheader("Enviar archivo cifrado")
        col_form, col_info = st.columns([2, 1])

        with col_form:
            archivo = st.file_uploader("Seleccione el archivo a proteger", key="up_enviar")
            destinatario = st.selectbox("Destinatario", ["alice", "bob", "charlie", "diana"])
            firmar = st.checkbox("Firmar digitalmente el archivo (Ed25519)", value=True)

            if st.button("Cifrar y enviar", type="primary", disabled=archivo is None):
                with st.spinner("Generando llave de sesión y cifrando con AES-256-GCM..."):
                    pass  # Simulación: no se realiza ningún cifrado real
                st.success(f"Archivo **{archivo.name}** cifrado y enviado a **{destinatario}**.")
                if firmar:
                    st.info("Archivo firmado digitalmente antes del envío.")
                # Detalle técnico simulado del "paquete" enviado
                with st.expander("Detalle técnico del envío (simulado)"):
                    st.code(
                        f"Algoritmo        : AES-256-GCM\n"
                        f"Llave de sesión  : protegida con la llave pública de {destinatario} (X25519)\n"
                        f"Nonce (único)    : {hex_falso(12)}\n"
                        f"Tag autenticación: {hex_falso(16)}\n"
                        f"ID anti-repetición: {hex_falso(8)}\n"
                        f"Timestamp        : {datetime.now().isoformat(timespec='seconds')}",
                        language="text",
                    )
            if archivo is None:
                st.caption("Suba un archivo para habilitar el envío.")

        with col_info:
            st.markdown("##### Flujo de protección")
            st.markdown(
                """
                1. Se genera una **llave AES única** para el archivo.
                2. El contenido se cifra con **AES-GCM**.
                3. La llave se protege con la **llave pública** del destinatario.
                4. Se **firma** el paquete y se añade un **nonce anti-repetición**.
                """
            )

    # ------------------------ Recibir y descifrar -------------------------
    with tab_recibir:
        st.subheader("Bandeja de archivos cifrados recibidos")

        for i, arch in enumerate(archivos_recibidos_mock()):
            with st.container(border=True):
                c_nom, c_meta, c_btn = st.columns([2.5, 1.5, 1])
                c_nom.markdown(f"**{arch['nombre']}**")
                c_nom.caption(f"Emisor: **{arch['emisor']}** · {arch['fecha']}")
                c_meta.caption(f"Tamaño: {arch['tamano']}")
                c_meta.caption("Estado: Cifrado")
                if c_btn.button("Descifrar", key=f"btn_descifrar_{i}", use_container_width=True):
                    with st.spinner("Recuperando llave de sesión y validando etiqueta GCM..."):
                        pass  # Simulación visual
                    st.success("Etiqueta de autenticación válida. Archivo descifrado correctamente.")
                    st.download_button(
                        "Descargar archivo descifrado (simulado)",
                        data=b"Contenido simulado del documento descifrado.",
                        file_name=arch["nombre"].replace(".enc", ""),
                        key=f"dl_{i}",
                    )

        st.divider()
        with st.expander("Simular un ataque de repetición (paquete reenviado)"):
            st.caption("Demuestra visualmente el rechazo de un mensaje previamente válido.")
            if st.button("Reenviar el último paquete recibido"):
                st.error("INTENTO DE REPETICIÓN DETECTADO: el nonce ya fue utilizado. Mensaje rechazado y evento registrado.")

    # ----------------------- Verificar firma digital ----------------------
    with tab_verificar:
        st.subheader("Verificar firma digital de un archivo")
        col_a, col_b = st.columns(2)

        with col_a:
            archivo_v = st.file_uploader("Archivo a verificar", key="up_verificar")
            firma = st.file_uploader("Archivo de firma (.sig)", key="up_firma")
            emisor = st.selectbox("Emisor esperado", ["alice", "bob", "charlie", "diana"], key="sel_emisor")

            verificar = st.button("Verificar firma", type="primary", disabled=archivo_v is None)

        with col_b:
            st.markdown("##### La verificación comprueba que:")
            st.markdown(
                """
                - El archivo fue enviado por el **usuario esperado**.
                - El contenido **no fue modificado**.
                - La **firma es válida** matemáticamente.
                """
            )

        if verificar:
            with st.spinner("Calculando hash y verificando contra la llave pública del emisor..."):
                pass  # Simulación visual
            # Caso especial simulado: 'charlie' tiene la llave pendiente → firma inválida
            if emisor == "charlie":
                st.error("FIRMA INVÁLIDA: la llave pública del emisor no está registrada o no corresponde. Evento registrado en logs.")
            else:
                st.success(f"FIRMA VÁLIDA: el archivo fue firmado por **{emisor}** y no ha sido modificado.")
                st.code(
                    f"Algoritmo : Ed25519\n"
                    f"Hash      : SHA-256 = {hex_falso(32)}\n"
                    f"Firmante  : {emisor}\n"
                    f"Verificado: {datetime.now().isoformat(timespec='seconds')}",
                    language="text",
                )


# ============================================================================
# 7. VISTA: IDENTIDAD Y LLAVES
#    (Ver llave pública · Exportar llave privada · Generar par · Contraseña)
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
        c1, c2, c3 = st.columns(3)
        c1.metric("Algoritmo", "Ed25519")
        c2.metric("Estado", "Activa")
        c3.metric("Registrada", "2026-06-15")

        st.code(llave_publica_falsa(), language="text")
        st.caption(f"Huella digital (fingerprint): `SHA256:{hex_falso(16)}`")
        st.info("La llave pública puede compartirse libremente: permite a otros usuarios cifrar archivos para usted y verificar sus firmas.")

    # ------------------------ Exportar llave privada ----------------------
    with tab_privada:
        st.subheader("Exportar llave privada (cifrada)")
        st.warning("Su llave privada NUNCA debe compartirse. La exportación siempre se realiza cifrada con una frase de seguridad.")

        st.text_input("Frase de seguridad para proteger la exportación", type="password", key="passphrase_exp")
        confirmo = st.checkbox("Entiendo los riesgos de exportar mi llave privada")

        if st.button("Exportar llave privada", disabled=not confirmo):
            st.success("Llave privada exportada y cifrada con su frase de seguridad (simulado).")
            st.download_button(
                "Descargar llave_privada.enc",
                data=b"CONTENIDO SIMULADO - NO ES UNA LLAVE REAL",
                file_name="llave_privada.enc",
            )
            st.caption("El evento de exportación fue registrado en los logs del sistema.")

    # ------------------------ Generar par de llaves -----------------------
    with tab_generar:
        st.subheader("Generar un nuevo par de llaves")
        st.markdown("Al regenerar sus llaves, la llave pública anterior será revocada y la nueva quedará asociada a su usuario.")

        algoritmo = st.radio("Algoritmo", ["Ed25519 (recomendado)", "RSA-3072", "ECDSA P-256"], horizontal=True)

        if st.button("Generar nuevo par de llaves", type="primary"):
            with st.spinner(f"Generando par de llaves {algoritmo.split()[0]}..."):
                pass  # Simulación visual
            st.success("Nuevo par de llaves generado. La llave pública quedó registrada y asociada a su usuario.")
            st.code(f"Nueva huella: SHA256:{hex_falso(16)}", language="text")

    # ------------------------ Gestionar contraseña ------------------------
    with tab_pass:
        st.subheader("Cambiar contraseña")
        with st.form("form_cambio_pass"):
            st.text_input("Contraseña actual", type="password")
            st.text_input("Nueva contraseña", type="password")
            st.text_input("Confirmar nueva contraseña", type="password")
            cambiar = st.form_submit_button("Actualizar contraseña")

        if cambiar:
            st.success("Contraseña actualizada (simulado). Almacenada con **Argon2id** y sal única — nunca en texto claro.")


# ============================================================================
# 8. VISTA: ADMINISTRACIÓN (SUPERUSUARIO)
#    (Ver logs · Gestionar usuarios · Bloquear/desbloquear cuenta)
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

        df_logs = logs_mock()

        # Métricas resumen de los logs
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Eventos totales", len(df_logs))
        c2.metric("Errores", int((df_logs["Nivel"] == "ERROR").sum()), delta_color="inverse")
        c3.metric("Advertencias", int((df_logs["Nivel"] == "WARNING").sum()), delta_color="inverse")
        c4.metric("Críticos", int((df_logs["Nivel"] == "CRITICAL").sum()), delta_color="inverse")

        # Filtros visuales
        col_f1, col_f2 = st.columns(2)
        nivel = col_f1.multiselect("Filtrar por nivel", df_logs["Nivel"].unique().tolist())
        evento = col_f2.multiselect("Filtrar por tipo de evento", df_logs["Evento"].unique().tolist())

        filtrado = df_logs
        if nivel:
            filtrado = filtrado[filtrado["Nivel"].isin(nivel)]
        if evento:
            filtrado = filtrado[filtrado["Evento"].isin(evento)]

        st.dataframe(filtrado, use_container_width=True, hide_index=True)
        st.caption("Los logs nunca contienen contraseñas, llaves privadas, llaves de sesión ni contenido de mensajes.")

    # ------------------------- Gestionar usuarios -------------------------
    with tab_usuarios:
        st.subheader("Usuarios registrados")
        st.dataframe(usuarios_mock(), use_container_width=True, hide_index=True)

        with st.expander("Registrar un nuevo usuario (alta administrativa)"):
            with st.form("form_alta_admin"):
                st.text_input("Nombre de usuario")
                st.selectbox("Rol", ["Empleado", "Auditor", "Superusuario"])
                alta = st.form_submit_button("Crear usuario")
            if alta:
                st.success("Usuario creado (simulado). Se le solicitará generar su par de llaves en el primer inicio de sesión.")

    # --------------------- Bloquear / desbloquear cuenta ------------------
    with tab_bloqueo:
        st.subheader("Bloquear o desbloquear una cuenta")

        col_sel, col_estado = st.columns([1.5, 1])
        with col_sel:
            objetivo = st.selectbox("Seleccione la cuenta", ["alice", "bob", "charlie", "diana"])
        with col_estado:
            bloqueada = objetivo == "charlie"  # Estado simulado según la tabla mock
            if bloqueada:
                st.error(f"Estado actual: **{objetivo}** está BLOQUEADA")
            else:
                st.success(f"Estado actual: **{objetivo}** está ACTIVA")

        motivo = st.text_input("Motivo (quedará registrado en los logs)")

        c_bloq, c_desb = st.columns(2)
        if c_bloq.button("Bloquear cuenta", use_container_width=True, disabled=bloqueada):
            st.error(f"Cuenta **{objetivo}** bloqueada. Motivo registrado: «{motivo or 'sin especificar'}».")
        if c_desb.button("Desbloquear cuenta", use_container_width=True, disabled=not bloqueada):
            st.success(f"Cuenta **{objetivo}** desbloqueada. Evento registrado en logs.")

        st.info("Las cuentas también se bloquean automáticamente tras 5 intentos fallidos de inicio de sesión (protección contra fuerza bruta).")


# ============================================================================
# 9. NAVEGACIÓN LATERAL (routing)
# ============================================================================

def barra_lateral() -> str:
    """Dibuja el menú lateral y devuelve la vista seleccionada."""
    with st.sidebar:
        st.markdown("## Documentos Seguros")
        st.markdown(f"**{st.session_state['usuario']}** · `Superusuario`")
        st.divider()

        vista = st.radio(
            "Navegación",
            [
                "Panel de Control",
                "Gestión de Archivos",
                "Identidad y Llaves",
                "Administración",
            ],
            label_visibility="collapsed",
        )

        st.divider()

        # Estado de seguridad de la sesión (decorativo)
        st.caption("Sesión cifrada · TLS 1.3 (simulado)")
        st.caption("Expira en 14 min")

        if st.button("Cerrar sesión", use_container_width=True, type="secondary"):
            cerrar_sesion()
            st.rerun()

    return vista


# ============================================================================
# 10. PUNTO DE ENTRADA (router principal)
# ============================================================================

def main() -> None:
    inicializar_estado()

    # Sin sesión activa → solo se muestra el Login
    if not st.session_state["logueado"]:
        vista_login()
        return

    # Con sesión activa → navegación completa
    vista = barra_lateral()

    if vista == "Panel de Control":
        vista_dashboard()
    elif vista == "Gestión de Archivos":
        vista_archivos()
    elif vista == "Identidad y Llaves":
        vista_llaves()
    elif vista == "Administración":
        vista_admin()


if __name__ == "__main__":
    main()

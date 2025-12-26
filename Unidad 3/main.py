import bcrypt
import requests
import oracledb
import os
import re
import flet as ft
from dotenv import load_dotenv
from typing import Optional, List, Dict, Tuple
from datetime import datetime
from decimal import Decimal

load_dotenv()


class Database:
    """Clase para gestionar la conexión y operaciones con Oracle Database"""
    
    def __init__(self, username: str, dsn: str, password: str):
        self.username = username
        self.dsn = dsn
        self.password = password
    
    def get_connection(self) -> oracledb.Connection:
        try:
            return oracledb.connect(
                user=self.username,
                password=self.password,
                dsn=self.dsn
            )
        except oracledb.DatabaseError as e:
            raise Exception(f"Error al conectar con la base de datos: {e}")
    
    def create_all_tables(self) -> None:
        """Crea todas las tablas necesarias del sistema"""
        tables = [
            """
            CREATE TABLE USERS (
                id INTEGER PRIMARY KEY,
                username VARCHAR2(32) UNIQUE NOT NULL,
                password VARCHAR2(128) NOT NULL,
                fecha_registro DATE DEFAULT SYSDATE,
                ultimo_acceso DATE
            )
            """,
            """
            CREATE TABLE INDICADORES_ECONOMICOS (
                id INTEGER PRIMARY KEY,
                nombre_indicador VARCHAR2(50) NOT NULL,
                valor NUMBER(18,4) NOT NULL,
                fecha_valor DATE NOT NULL,
                fecha_consulta DATE DEFAULT SYSDATE,
                usuario_consulta VARCHAR2(32) NOT NULL,
                sitio_proveedor VARCHAR2(255) NOT NULL,
                CONSTRAINT fk_usuario FOREIGN KEY (usuario_consulta) 
                    REFERENCES USERS(username)
            )
            """,
            """
            CREATE TABLE AUDITORIA_CONSULTAS (
                id INTEGER PRIMARY KEY,
                usuario VARCHAR2(32) NOT NULL,
                tipo_consulta VARCHAR2(100) NOT NULL,
                indicador_codigo VARCHAR2(20),
                fecha_solicitada VARCHAR2(20),
                fecha_hora_consulta TIMESTAMP DEFAULT SYSTIMESTAMP,
                resultado_exitoso CHAR(1) DEFAULT 'S',
                descripcion VARCHAR2(500),
                CONSTRAINT fk_usuario_auditoria FOREIGN KEY (usuario) 
                    REFERENCES USERS(username),
                CONSTRAINT chk_resultado CHECK (resultado_exitoso IN ('S', 'N'))
            )
            """,
            "CREATE SEQUENCE seq_users START WITH 1 INCREMENT BY 1",
            "CREATE SEQUENCE seq_indicadores START WITH 1 INCREMENT BY 1",
            "CREATE SEQUENCE seq_auditoria START WITH 1 INCREMENT BY 1"
        ]
        
        for table_sql in tables:
            try:
                self.query(table_sql)
            except Exception as e:
                if "ORA-00955" not in str(e) and "ORA-02289" not in str(e):
                    pass
    
    def query(self, sql: str, parameters: Optional[dict] = None) -> Optional[List[Tuple]]:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    if parameters:
                        cur.execute(sql, parameters)
                    else:
                        cur.execute(sql)
                    
                    if sql.strip().upper().startswith("SELECT"):
                        return cur.fetchall()
                    
                    conn.commit()
                    return None
        except oracledb.DatabaseError as e:
            raise


class Auditoria:
    """Clase para gestionar la auditoría de consultas del sistema"""
    
    @staticmethod
    def registrar_consulta(db: Database, usuario: str, tipo_consulta: str,
                          indicador_codigo: Optional[str] = None,
                          fecha_solicitada: Optional[str] = None,
                          resultado_exitoso: bool = True,
                          descripcion: Optional[str] = None) -> bool:
        try:
            sql = """
            INSERT INTO AUDITORIA_CONSULTAS 
            (id, usuario, tipo_consulta, indicador_codigo, fecha_solicitada,
             resultado_exitoso, descripcion)
            VALUES 
            (seq_auditoria.NEXTVAL, :p_usuario, :p_tipo, :p_codigo, :p_fecha,
             :p_exitoso, :p_descripcion)
            """
            
            parametros = {
                "p_usuario": usuario,
                "p_tipo": tipo_consulta,
                "p_codigo": indicador_codigo,
                "p_fecha": fecha_solicitada,
                "p_exitoso": 'S' if resultado_exitoso else 'N',
                "p_descripcion": descripcion
            }
            
            db.query(sql, parametros)
            return True
        except Exception:
            return False
    
    @staticmethod
    def obtener_consultas_usuario(db: Database, usuario: str, limite: int = 20) -> Optional[List[Tuple]]:
        try:
            sql = """
            SELECT tipo_consulta, indicador_codigo, fecha_solicitada,
            TO_CHAR(fecha_hora_consulta, 'DD-MM-YYYY HH24:MI:SS'),
            resultado_exitoso, descripcion
            FROM AUDITORIA_CONSULTAS
            WHERE usuario = :p_usuario
            ORDER BY fecha_hora_consulta DESC
            FETCH FIRST :p_limite ROWS ONLY
            """
            return db.query(sql, {"p_usuario": usuario, "p_limite": limite})
        except Exception:
            return None
    
    @staticmethod
    def obtener_estadisticas_usuario(db: Database, usuario: str) -> Optional[Dict]:
        try:
            sql = """
            SELECT 
            COUNT(*) as total_consultas,
            SUM(CASE WHEN resultado_exitoso = 'S' THEN 1 ELSE 0 END) as exitosas,
            SUM(CASE WHEN resultado_exitoso = 'N' THEN 1 ELSE 0 END) as fallidas,
            COUNT(DISTINCT indicador_codigo) as indicadores_distintos,
            TO_CHAR(MIN(fecha_hora_consulta), 'DD-MM-YYYY HH24:MI:SS') as primera_consulta,
            TO_CHAR(MAX(fecha_hora_consulta), 'DD-MM-YYYY HH24:MI:SS') as ultima_consulta
            FROM AUDITORIA_CONSULTAS
            WHERE usuario = :p_usuario
            """
            
            resultado = db.query(sql, {"p_usuario": usuario})
            
            if resultado and len(resultado) > 0:
                fila = resultado[0]
                return {
                    "total_consultas": fila[0] or 0,
                    "exitosas": fila[1] or 0,
                    "fallidas": fila[2] or 0,
                    "indicadores_distintos": fila[3] or 0,
                    "primera_consulta": fila[4] or "N/A",
                    "ultima_consulta": fila[5] or "N/A"
                }
            return None
        except Exception:
            return None


class Validador:
    """Clase para validar entradas de usuario"""
    
    @staticmethod
    def validar_username(username: str) -> Tuple[bool, str]:
        if not username or len(username.strip()) == 0:
            return False, "El nombre de usuario no puede estar vacío"
        if len(username) < 4:
            return False, "El nombre de usuario debe tener al menos 4 caracteres"
        if len(username) > 32:
            return False, "El nombre de usuario no puede exceder 32 caracteres"
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Solo puede contener letras, números y guión bajo"
        return True, ""
    
    @staticmethod
    def validar_password(password: str) -> Tuple[bool, str]:
        if not password or len(password.strip()) == 0:
            return False, "La contraseña no puede estar vacía"
        if len(password) < 8:
            return False, "La contraseña debe tener al menos 8 caracteres"
        if len(password) > 64:
            return False, "La contraseña no puede exceder 64 caracteres"
        
        tiene_mayuscula = any(c.isupper() for c in password)
        tiene_minuscula = any(c.islower() for c in password)
        tiene_numero = any(c.isdigit() for c in password)
        
        if not (tiene_mayuscula and tiene_minuscula and tiene_numero):
            return False, "Debe contener mayúsculas, minúsculas y números"
        return True, ""
    
    @staticmethod
    def validar_fecha(fecha_str: str) -> Tuple[bool, str, Optional[str]]:
        if not fecha_str:
            return True, "", None
        
        if not re.match(r'^\d{2}-\d{2}-\d{4}$', fecha_str):
            return False, "Formato inválido. Use DD-MM-YYYY", None
        
        try:
            partes = fecha_str.split('-')
            dia, mes, anio = int(partes[0]), int(partes[1]), int(partes[2])
            
            if not (1 <= mes <= 12):
                return False, "Mes inválido (1-12)", None
            if not (1 <= dia <= 31):
                return False, "Día inválido (1-31)", None
            if not (2000 <= anio <= 2100):
                return False, "Año fuera de rango (2000-2100)", None
            
            fecha = datetime(anio, mes, dia)
            return True, "", fecha.strftime("%d-%m-%Y")
        except ValueError as e:
            return False, f"Fecha inválida: {e}", None
    
    @staticmethod
    def sanitizar_input(texto: str) -> str:
        texto = texto.strip()
        texto = re.sub(r'[;\'"\\<>]', '', texto)
        return texto


class Auth:
    """Clase para gestionar autenticación"""
    
    @staticmethod
    def login(db: Database, username: str, password: str) -> Tuple[bool, str]:
        try:
            username = Validador.sanitizar_input(username)
            resultado = db.query(
                "SELECT username, password FROM USERS WHERE username = :p_username",
                {"p_username": username}
            )
            
            if not resultado or len(resultado) == 0:
                Auditoria.registrar_consulta(db, username, "LOGIN_FALLIDO", 
                                            resultado_exitoso=False,
                                            descripcion="Usuario no encontrado")
                return False, "Usuario no encontrado"
            
            stored_hash = resultado[0][1]
            if isinstance(stored_hash, str):
                stored_hash_bytes = bytes.fromhex(stored_hash)
            else:
                stored_hash_bytes = stored_hash
            
            password_bytes = password.encode("UTF-8")
            
            if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                db.query("UPDATE USERS SET ultimo_acceso = SYSDATE WHERE username = :p_username",
                        {"p_username": username})
                Auditoria.registrar_consulta(db, username, "LOGIN_EXITOSO",
                                            resultado_exitoso=True,
                                            descripcion="Inicio de sesión correcto")
                return True, f"¡Bienvenido {username}!"
            else:
                Auditoria.registrar_consulta(db, username, "LOGIN_FALLIDO",
                                            resultado_exitoso=False,
                                            descripcion="Contraseña incorrecta")
                return False, "Contraseña incorrecta"
        except Exception as e:
            return False, f"Error durante el login: {e}"
    
    @staticmethod
    def register(db: Database, username: str, password: str) -> Tuple[bool, str]:
        try:
            es_valido, mensaje = Validador.validar_username(username)
            if not es_valido:
                return False, mensaje
            
            es_valido, mensaje = Validador.validar_password(password)
            if not es_valido:
                return False, mensaje
            
            username = Validador.sanitizar_input(username)
            
            resultado = db.query("SELECT username FROM USERS WHERE username = :p_username",
                               {"p_username": username})
            
            if resultado and len(resultado) > 0:
                return False, "El nombre de usuario ya está registrado"
            
            password_bytes = password.encode("UTF-8")
            salt = bcrypt.gensalt(rounds=12)
            hashed_password = bcrypt.hashpw(password_bytes, salt)
            hash_hex = hashed_password.hex()
            
            db.query("""
                INSERT INTO USERS (id, username, password) 
                VALUES (seq_users.NEXTVAL, :p_username, :p_password)
                """,
                {"p_username": username, "p_password": hash_hex}
            )
            
            Auditoria.registrar_consulta(db, username, "REGISTRO_USUARIO",
                                        resultado_exitoso=True,
                                        descripcion="Usuario registrado en el sistema")
            
            return True, f"Usuario '{username}' registrado exitosamente"
        except Exception as e:
            return False, f"Error durante el registro: {e}"


class IndicadorEconomico:
    """Clase para deserializar datos de indicadores económicos"""
    
    def __init__(self, nombre: str, valor: float, fecha: datetime, 
                 codigo: str, unidad_medida: str):
        self.nombre = nombre
        self.valor = valor
        self.fecha = fecha
        self.codigo = codigo
        self.unidad_medida = unidad_medida
    
    @classmethod
    def from_json(cls, json_data: dict, codigo: str) -> 'IndicadorEconomico':
        try:
            nombre = json_data.get('nombre', codigo.upper())
            unidad_medida = json_data.get('unidad_medida', '')
            serie = json_data.get('serie', [])
            
            if not serie:
                raise ValueError("No hay datos disponibles")
            
            primer_dato = serie[0]
            valor = float(primer_dato.get('valor', 0))
            fecha_str = primer_dato.get('fecha', '')
            fecha = datetime.fromisoformat(fecha_str.replace('Z', '+00:00'))
            
            return cls(nombre, valor, fecha, codigo, unidad_medida)
        except Exception as e:
            raise ValueError(f"Error al deserializar: {e}")
    
    def __str__(self) -> str:
        fecha_formateada = self.fecha.strftime("%d-%m-%Y")
        return f"{self.nombre}: ${self.valor:,.2f} ({fecha_formateada})"


class Finance:
    """Clase para consultar indicadores económicos"""
    
    INDICADORES = {
        'uf': 'Unidad de Fomento (UF)',
        'ivp': 'Índice de Valor Promedio (IVP)',
        'ipc': 'Índice de Precio al Consumidor (IPC)',
        'utm': 'Unidad Tributaria Mensual (UTM)',
        'dolar': 'Dólar Observado',
        'euro': 'Euro'
    }
    
    def __init__(self, base_url: str = "https://mindicador.cl/api"):
        self.base_url = base_url
    
    def get_indicator(self, codigo_indicador: str, fecha: Optional[str] = None,
                     db: Optional[Database] = None, usuario: Optional[str] = None) -> Optional[IndicadorEconomico]:
        try:
            url = f"{self.base_url}/{codigo_indicador}/{fecha}" if fecha else f"{self.base_url}/{codigo_indicador}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            json_data = response.json()
            indicador = IndicadorEconomico.from_json(json_data, codigo_indicador)
            
            if db and usuario:
                Auditoria.registrar_consulta(db, usuario, "CONSULTA_INDICADOR",
                                            indicador_codigo=codigo_indicador,
                                            fecha_solicitada=fecha,
                                            resultado_exitoso=True,
                                            descripcion=f"Consulta de {indicador.nombre}")
            return indicador
        except Exception as e:
            if db and usuario:
                Auditoria.registrar_consulta(db, usuario, "CONSULTA_INDICADOR",
                                            indicador_codigo=codigo_indicador,
                                            fecha_solicitada=fecha,
                                            resultado_exitoso=False,
                                            descripcion=str(e)[:200])
            return None
    
    def registrar_indicador(self, db: Database, indicador: IndicadorEconomico,
                           usuario: str) -> Tuple[bool, str]:
        try:
            sql = """
            INSERT INTO INDICADORES_ECONOMICOS 
            (id, nombre_indicador, valor, fecha_valor, fecha_consulta, 
             usuario_consulta, sitio_proveedor)
            VALUES 
            (seq_indicadores.NEXTVAL, :p_nombre, :p_valor, :p_fecha_valor, 
             SYSDATE, :p_usuario, :p_sitio)
            """
            
            db.query(sql, {
                "p_nombre": indicador.nombre,
                "p_valor": indicador.valor,
                "p_fecha_valor": indicador.fecha,
                "p_usuario": usuario,
                "p_sitio": self.base_url
            })
            
            Auditoria.registrar_consulta(db, usuario, "REGISTRO_INDICADOR",
                                        indicador_codigo=indicador.codigo,
                                        resultado_exitoso=True,
                                        descripcion=f"Indicador registrado en BD")
            
            return True, "Indicador registrado exitosamente"
        except Exception as e:
            Auditoria.registrar_consulta(db, usuario, "REGISTRO_INDICADOR",
                                        indicador_codigo=indicador.codigo,
                                        resultado_exitoso=False,
                                        descripcion=str(e)[:200])
            return False, f"Error: {e}"


def main(page: ft.Page):
    page.title = "Sistema de Indicadores Económicos"
    page.window.width = 900
    page.window.height = 700
    page.padding = 0
    page.theme_mode = ft.ThemeMode.LIGHT
    
    # Inicializar base de datos
    try:
        db = Database(
            username=os.getenv("ORACLE_USER"),
            dsn=os.getenv("ORACLE_DSN"),
            password=os.getenv("ORACLE_PASSWORD")
        )
        db.create_all_tables()
    except Exception as e:
        page.add(ft.Text(f"Error de conexión: {e}", color=ft.Colors.RED))
        return
    
    finance = Finance()
    usuario_actual = {"username": None}
    
    # Función para mostrar mensajes
    def mostrar_mensaje(mensaje: str, es_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(mensaje),
            bgcolor=ft.Colors.RED_400 if es_error else ft.Colors.GREEN_400
        )
        page.overlay.append(snack)
        snack.open = True
        page.update()
    
    # Vista de Login/Registro
    def vista_auth():
        username_field = ft.TextField(label="Usuario", width=300)
        password_field = ft.TextField(label="Contraseña", password=True, can_reveal_password=True, width=300)
        
        def handle_login(e):
            if not username_field.value or not password_field.value:
                mostrar_mensaje("Complete todos los campos", True)
                return
            
            exito, mensaje = Auth.login(db, username_field.value, password_field.value)
            if exito:
                usuario_actual["username"] = username_field.value
                mostrar_mensaje(mensaje)
                page.go("/menu")
            else:
                mostrar_mensaje(mensaje, True)
        
        def handle_register(e):
            if not username_field.value or not password_field.value:
                mostrar_mensaje("Complete todos los campos", True)
                return
            
            exito, mensaje = Auth.register(db, username_field.value, password_field.value)
            mostrar_mensaje(mensaje, not exito)
            if exito:
                username_field.value = ""
                password_field.value = ""
                page.update()
        
        return ft.View(
            "/",
            [
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("SISTEMA DE INDICADORES ECONÓMICOS", 
                                   size=24, weight=ft.FontWeight.BOLD,
                                   text_align=ft.TextAlign.CENTER),
                            ft.Text("EcoTech Solutions", size=16, color=ft.Colors.GREY_700),
                            ft.Divider(height=30),
                            username_field,
                            password_field,
                            ft.Row(
                                [
                                    ft.ElevatedButton("Iniciar Sesión", 
                                                     on_click=handle_login,
                                                     style=ft.ButtonStyle(
                                                         bgcolor=ft.Colors.BLUE_700,
                                                         color=ft.Colors.WHITE
                                                     )),
                                    ft.OutlinedButton("Registrarse", on_click=handle_register),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                spacing=10
                            )
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=15
                    ),
                    padding=40,
                    bgcolor=ft.Colors.WHITE,
                    border_radius=10,
                    shadow=ft.BoxShadow(blur_radius=10, color=ft.Colors.GREY_300)
                )
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            bgcolor=ft.Colors.BLUE_50
        )
    
    # Vista del Menú Principal
    def vista_menu():
        def crear_boton_menu(texto, ruta, icono):
            return ft.Container(
                content=ft.Column(
                    [
                        ft.Icon(icono, size=40, color=ft.Colors.BLUE_700),
                        ft.Text(texto, size=14, text_align=ft.TextAlign.CENTER, weight=ft.FontWeight.W_500)
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=10
                ),
                padding=20,
                bgcolor=ft.Colors.WHITE,
                border_radius=10,
                shadow=ft.BoxShadow(blur_radius=5, color=ft.Colors.GREY_300),
                on_click=lambda _: page.go(ruta),
                width=200,
                height=150
            )
        
        return ft.View(
            "/menu",
            [
                ft.AppBar(
                    title=ft.Text(f"Bienvenido: {usuario_actual['username']}"),
                    bgcolor=ft.Colors.BLUE_700,
                    actions=[
                        ft.IconButton(
                            icon=ft.Icons.LOGOUT,
                            tooltip="Cerrar Sesión",
                            on_click=lambda _: cerrar_sesion()
                        )
                    ]
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Menú Principal", size=28, weight=ft.FontWeight.BOLD),
                            ft.Divider(height=20),
                            ft.Row(
                                [
                                    crear_boton_menu("Consultar\nIndicador", "/consultar", ft.Icons.SEARCH),
                                    crear_boton_menu("Registrar\nIndicador", "/registrar", ft.Icons.SAVE),
                                    crear_boton_menu("Historial", "/historial", ft.Icons.HISTORY),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                spacing=20,
                                wrap=True
                            ),
                            ft.Row(
                                [
                                    crear_boton_menu("Auditoría", "/auditoria", ft.Icons.ASSESSMENT),
                                    crear_boton_menu("Estadísticas", "/estadisticas", ft.Icons.BAR_CHART),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                spacing=20,
                                wrap=True
                            )
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=20
                    ),
                    padding=40
                )
            ],
            bgcolor=ft.Colors.BLUE_50
        )
    
    def cerrar_sesion():
        if usuario_actual["username"]:
            Auditoria.registrar_consulta(db, usuario_actual["username"], "LOGOUT",
                                        resultado_exitoso=True,
                                        descripcion="Cierre de sesión")
            usuario_actual["username"] = None
        page.go("/")
    
    # Vista Consultar Indicador
    def vista_consultar():
        dropdown = ft.Dropdown(
            label="Seleccione un indicador",
            options=[ft.dropdown.Option(k, v) for k, v in Finance.INDICADORES.items()],
            width=400
        )
        fecha_field = ft.TextField(
            label="Fecha (DD-MM-YYYY)",
            hint_text="Dejar vacío para hoy",
            width=400
        )
        resultado_text = ft.Text("", size=16)
        
        def consultar(e):
            if not dropdown.value:
                mostrar_mensaje("Seleccione un indicador", True)
                return
            
            fecha = fecha_field.value if fecha_field.value else None
            if fecha:
                es_valida, mensaje, fecha_norm = Validador.validar_fecha(fecha)
                if not es_valida:
                    mostrar_mensaje(mensaje, True)
                    return
                fecha = fecha_norm
            
            indicador = finance.get_indicator(dropdown.value, fecha, db, usuario_actual["username"])
            
            if indicador:
                resultado_text.value = f"✓ {indicador}"
                resultado_text.color = ft.Colors.GREEN_700
                mostrar_mensaje("Consulta exitosa")
            else:
                resultado_text.value = "✗ No se pudo obtener el indicador"
                resultado_text.color = ft.Colors.RED_700
                mostrar_mensaje("Error en la consulta", True)
            
            page.update()
        
        return ft.View(
            "/consultar",
            [
                ft.AppBar(
                    title=ft.Text("Consultar Indicador"),
                    bgcolor=ft.Colors.BLUE_700,
                    leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: page.go("/menu"))
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Consulta de Indicadores Económicos", size=24, weight=ft.FontWeight.BOLD),
                            ft.Divider(height=20),
                            dropdown,
                            fecha_field,
                            ft.ElevatedButton("Consultar", on_click=consultar, 
                                            style=ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700)),
                            ft.Divider(height=20),
                            resultado_text
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=15
                    ),
                    padding=40
                )
            ],
            bgcolor=ft.Colors.BLUE_50
        )
    
    # Vista Registrar Indicador
    def vista_registrar():
        dropdown = ft.Dropdown(
            label="Seleccione un indicador",
            options=[ft.dropdown.Option(k, v) for k, v in Finance.INDICADORES.items()],
            width=400
        )
        fecha_field = ft.TextField(label="Fecha (DD-MM-YYYY)", hint_text="Dejar vacío para hoy", width=400)
        resultado_container = ft.Column([], spacing=10)
        
        def consultar_y_registrar(e):
            if not dropdown.value:
                mostrar_mensaje("Seleccione un indicador", True)
                return
            
            fecha = fecha_field.value if fecha_field.value else None
            if fecha:
                es_valida, mensaje, fecha_norm = Validador.validar_fecha(fecha)
                if not es_valida:
                    mostrar_mensaje(mensaje, True)
                    return
                fecha = fecha_norm
            
            indicador = finance.get_indicator(dropdown.value, fecha, db, usuario_actual["username"])
            
            if indicador:
                resultado_container.controls.clear()
                resultado_container.controls.append(
                    ft.Text(f"✓ {indicador}", size=16, color=ft.Colors.GREEN_700)
                )
                
                def registrar_ahora(e):
                    exito, msg = finance.registrar_indicador(db, indicador, usuario_actual["username"])
                    mostrar_mensaje(msg, not exito)
                    if exito:
                        resultado_container.controls.clear()
                        page.update()
                
                resultado_container.controls.append(
                    ft.ElevatedButton("Registrar en BD", on_click=registrar_ahora,
                                    style=ft.ButtonStyle(bgcolor=ft.Colors.GREEN_700))
                )
                mostrar_mensaje("Consulta exitosa")
            else:
                resultado_container.controls.clear()
                resultado_container.controls.append(
                    ft.Text("✗ No se pudo obtener el indicador", color=ft.Colors.RED_700)
                )
                mostrar_mensaje("Error en la consulta", True)
            
            page.update()
        
        return ft.View(
            "/registrar",
            [
                ft.AppBar(
                    title=ft.Text("Consultar y Registrar"),
                    bgcolor=ft.Colors.BLUE_700,
                    leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: page.go("/menu"))
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Consultar y Registrar Indicador", size=24, weight=ft.FontWeight.BOLD),
                            ft.Divider(height=20),
                            dropdown,
                            fecha_field,
                            ft.ElevatedButton("Consultar", on_click=consultar_y_registrar,
                                            style=ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700)),
                            ft.Divider(height=20),
                            resultado_container
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=15
                    ),
                    padding=40
                )
            ],
            bgcolor=ft.Colors.BLUE_50
        )
    
    # Vista Historial
    def vista_historial():
        tabla = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("Indicador", weight=ft.FontWeight.BOLD)),
                ft.DataColumn(ft.Text("Valor", weight=ft.FontWeight.BOLD)),
                ft.DataColumn(ft.Text("Fecha Indicador", weight=ft.FontWeight.BOLD)),
                ft.DataColumn(ft.Text("Fecha Consulta", weight=ft.FontWeight.BOLD)),
            ],
            rows=[],
            border=ft.border.all(1, ft.Colors.GREY_300),
            border_radius=10,
            horizontal_lines=ft.border.BorderSide(1, ft.Colors.GREY_200)
        )
        
        def cargar_historial():
            try:
                resultados = db.query(
                    """
                    SELECT nombre_indicador, valor, 
                           TO_CHAR(fecha_valor, 'DD-MM-YYYY'),
                           TO_CHAR(fecha_consulta, 'DD-MM-YYYY HH24:MI:SS'),
                           usuario_consulta
                    FROM INDICADORES_ECONOMICOS
                    WHERE usuario_consulta = :p_usuario
                    ORDER BY fecha_consulta DESC
                    """,
                    {"p_usuario": usuario_actual["username"]}
                )
                
                tabla.rows.clear()
                if resultados and len(resultados) > 0:
                    for fila in resultados:
                        tabla.rows.append(
                            ft.DataRow(
                                cells=[
                                    ft.DataCell(ft.Text(fila[0])),
                                    ft.DataCell(ft.Text(f"${fila[1]:,.2f}")),
                                    ft.DataCell(ft.Text(fila[2])),
                                    ft.DataCell(ft.Text(fila[3])),
                                ]
                            )
                        )
                    mostrar_mensaje(f"Se encontraron {len(resultados)} registros")
                else:
                    mostrar_mensaje("No hay registros", True)
                
                page.update()
            except Exception as e:
                mostrar_mensaje(f"Error: {e}", True)
        
        cargar_historial()
        
        return ft.View(
            "/historial",
            [
                ft.AppBar(
                    title=ft.Text("Historial de Indicadores"),
                    bgcolor=ft.Colors.BLUE_700,
                    leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: page.go("/menu"))
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Historial de Consultas", size=24, weight=ft.FontWeight.BOLD),
                            ft.Divider(height=20),
                            ft.Container(
                                content=ft.Column(
                                    [tabla],
                                    scroll=ft.ScrollMode.AUTO
                                ),
                                height=500
                            ),
                            ft.ElevatedButton(
                                "Actualizar",
                                icon=ft.Icons.REFRESH,
                                on_click=lambda _: cargar_historial(),
                                style=ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700)
                            )
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=15
                    ),
                    padding=40
                )
            ],
            bgcolor=ft.Colors.BLUE_50
        )
    
    # Vista Auditoría
    def vista_auditoria():
        lista_auditoria = ft.Column([], spacing=10, scroll=ft.ScrollMode.AUTO)
        
        def cargar_auditoria():
            resultados = Auditoria.obtener_consultas_usuario(db, usuario_actual["username"], limite=30)
            
            lista_auditoria.controls.clear()
            if resultados and len(resultados) > 0:
                for i, fila in enumerate(resultados, 1):
                    tipo_consulta = fila[0]
                    indicador = fila[1] or "N/A"
                    fecha_solicitada = fila[2] or "N/A"
                    fecha_hora = fila[3]
                    exitoso = fila[4] == 'S'
                    descripcion = fila[5] or ""
                    
                    card = ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Icon(
                                            ft.Icons.CHECK_CIRCLE if exitoso else ft.Icons.ERROR,
                                            color=ft.Colors.GREEN_700 if exitoso else ft.Colors.RED_700,
                                            size=20
                                        ),
                                        ft.Text(tipo_consulta, weight=ft.FontWeight.BOLD, size=16)
                                    ],
                                    spacing=10
                                ),
                                ft.Text(f"Fecha/Hora: {fecha_hora}", size=12),
                                ft.Text(f"Indicador: {indicador}", size=12) if indicador != "N/A" else ft.Container(),
                                ft.Text(f"Fecha solicitada: {fecha_solicitada}", size=12) if fecha_solicitada != "N/A" else ft.Container(),
                                ft.Text(f"Descripción: {descripcion}", size=12, italic=True) if descripcion else ft.Container(),
                            ],
                            spacing=5
                        ),
                        padding=15,
                        bgcolor=ft.Colors.WHITE,
                        border_radius=10,
                        border=ft.border.all(1, ft.Colors.GREEN_200 if exitoso else ft.Colors.RED_200)
                    )
                    lista_auditoria.controls.append(card)
                
                mostrar_mensaje(f"Se encontraron {len(resultados)} registros")
            else:
                lista_auditoria.controls.append(
                    ft.Text("No hay consultas registradas", size=16, color=ft.Colors.GREY_700)
                )
            
            page.update()
        
        cargar_auditoria()
        
        return ft.View(
            "/auditoria",
            [
                ft.AppBar(
                    title=ft.Text("Auditoría de Consultas"),
                    bgcolor=ft.Colors.BLUE_700,
                    leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: page.go("/menu"))
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Historial de Auditoría", size=24, weight=ft.FontWeight.BOLD),
                            ft.Divider(height=20),
                            ft.Container(
                                content=lista_auditoria,
                                height=500
                            ),
                            ft.ElevatedButton(
                                "Actualizar",
                                icon=ft.Icons.REFRESH,
                                on_click=lambda _: cargar_auditoria(),
                                style=ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700)
                            )
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=15
                    ),
                    padding=40
                )
            ],
            bgcolor=ft.Colors.BLUE_50
        )
    
    # Vista Estadísticas
    def vista_estadisticas():
        stats_container = ft.Column([], spacing=15)
        
        def cargar_estadisticas():
            stats = Auditoria.obtener_estadisticas_usuario(db, usuario_actual["username"])
            
            stats_container.controls.clear()
            if stats:
                tasa_exito = (stats['exitosas'] / stats['total_consultas'] * 100) if stats['total_consultas'] > 0 else 0
                
                # Crear tarjetas de estadísticas
                cards = [
                    ("Total de Consultas", str(stats['total_consultas']), ft.Icons.SEARCH, ft.Colors.BLUE_700),
                    ("Consultas Exitosas", str(stats['exitosas']), ft.Icons.CHECK_CIRCLE, ft.Colors.GREEN_700),
                    ("Consultas Fallidas", str(stats['fallidas']), ft.Icons.ERROR, ft.Colors.RED_700),
                    ("Tasa de Éxito", f"{tasa_exito:.1f}%", ft.Icons.TRENDING_UP, ft.Colors.ORANGE_700),
                    ("Indicadores Distintos", str(stats['indicadores_distintos']), ft.Icons.ANALYTICS, ft.Colors.PURPLE_700),
                ]
                
                for titulo, valor, icono, color in cards:
                    card = ft.Container(
                        content=ft.Column(
                            [
                                ft.Icon(icono, size=40, color=color),
                                ft.Text(titulo, size=14, weight=ft.FontWeight.W_500, text_align=ft.TextAlign.CENTER),
                                ft.Text(valor, size=24, weight=ft.FontWeight.BOLD, color=color)
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=10
                        ),
                        padding=20,
                        bgcolor=ft.Colors.WHITE,
                        border_radius=10,
                        shadow=ft.BoxShadow(blur_radius=5, color=ft.Colors.GREY_300),
                        width=180,
                        height=150
                    )
                    stats_container.controls.append(card)
                
                # Información adicional
                stats_container.controls.append(ft.Divider(height=20))
                stats_container.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text("Información Temporal", size=18, weight=ft.FontWeight.BOLD),
                                ft.Text(f"Primera consulta: {stats['primera_consulta']}", size=14),
                                ft.Text(f"Última consulta: {stats['ultima_consulta']}", size=14),
                            ],
                            spacing=10
                        ),
                        padding=20,
                        bgcolor=ft.Colors.WHITE,
                        border_radius=10,
                        border=ft.border.all(1, ft.Colors.GREY_300)
                    )
                )
                
                mostrar_mensaje("Estadísticas cargadas")
            else:
                stats_container.controls.append(
                    ft.Text("No hay estadísticas disponibles", size=16, color=ft.Colors.GREY_700)
                )
            
            page.update()
        
        cargar_estadisticas()
        
        return ft.View(
            "/estadisticas",
            [
                ft.AppBar(
                    title=ft.Text("Estadísticas de Uso"),
                    bgcolor=ft.Colors.BLUE_700,
                    leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=lambda _: page.go("/menu"))
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Estadísticas del Usuario", size=24, weight=ft.FontWeight.BOLD),
                            ft.Divider(height=20),
                            ft.Container(
                                content=ft.Column(
                                    [
                                        ft.Row(
                                            stats_container.controls[:3] if len(stats_container.controls) > 0 else [],
                                            alignment=ft.MainAxisAlignment.CENTER,
                                            spacing=20,
                                            wrap=True
                                        ),
                                        ft.Row(
                                            stats_container.controls[3:5] if len(stats_container.controls) > 3 else [],
                                            alignment=ft.MainAxisAlignment.CENTER,
                                            spacing=20,
                                            wrap=True
                                        ),
                                        stats_container.controls[6] if len(stats_container.controls) > 6 else ft.Container(),
                                        stats_container.controls[7] if len(stats_container.controls) > 7 else ft.Container(),
                                    ],
                                    scroll=ft.ScrollMode.AUTO
                                ),
                                height=500
                            ),
                            ft.ElevatedButton(
                                "Actualizar",
                                icon=ft.Icons.REFRESH,
                                on_click=lambda _: cargar_estadisticas(),
                                style=ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700)
                            )
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=15
                    ),
                    padding=40
                )
            ], 
            bgcolor=ft.Colors.BLUE_50
        )
    
    # Manejo de rutas
    def route_change(route):
        page.views.clear()
        
        if page.route == "/":
            page.views.append(vista_auth())
        elif page.route == "/menu":
            if not usuario_actual["username"]:
                page.go("/")
                return
            page.views.append(vista_menu())
        elif page.route == "/consultar":
            if not usuario_actual["username"]:
                page.go("/")
                return
            page.views.append(vista_consultar())
        elif page.route == "/registrar":
            if not usuario_actual["username"]:
                page.go("/")
                return
            page.views.append(vista_registrar())
        elif page.route == "/historial":
            if not usuario_actual["username"]:
                page.go("/")
                return
            page.views.append(vista_historial())
        elif page.route == "/auditoria":
            if not usuario_actual["username"]:
                page.go("/")
                return
            page.views.append(vista_auditoria())
        elif page.route == "/estadisticas":
            if not usuario_actual["username"]:
                page.go("/")
                return
            page.views.append(vista_estadisticas())
        
        page.update()
    
    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)
    
    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go(page.route)


if __name__ == "__main__":
    ft.app(target=main)
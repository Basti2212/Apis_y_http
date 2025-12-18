import bcrypt
import requests
import oracledb
import os
import re
from dotenv import load_dotenv
from typing import Optional, List, Dict, Tuple
from datetime import datetime
from decimal import Decimal

# Variables de entorno
load_dotenv()


class Database:
    """Clase para gestionar la conexión y operaciones con Oracle Database"""
    
    def __init__(self, username: str, dsn: str, password: str):
        """
        Inicializa la conexión a la base de datos
        
        Args:
            username: Usuario de Oracle
            dsn: Data Source Name de Oracle
            password: Contraseña de Oracle
        """
        self.username = username
        self.dsn = dsn
        self.password = password
    
    def get_connection(self) -> oracledb.Connection:
        """
        Obtiene una conexión a la base de datos
        
        Returns:
            Objeto de conexión a Oracle
        """
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
            # Tabla de usuarios con autenticación
            """
            CREATE TABLE USERS (
                id INTEGER PRIMARY KEY,
                username VARCHAR2(32) UNIQUE NOT NULL,
                password VARCHAR2(128) NOT NULL,
                fecha_registro DATE DEFAULT SYSDATE,
                ultimo_acceso DATE
            )
            """,
            
            # Tabla de indicadores económicos
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
            
            # NUEVA TABLA: Auditoría de consultas de usuarios
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
            
            # Secuencia para IDs de usuarios
            "CREATE SEQUENCE seq_users START WITH 1 INCREMENT BY 1",
            
            # Secuencia para IDs de indicadores
            "CREATE SEQUENCE seq_indicadores START WITH 1 INCREMENT BY 1",
            
            # Secuencia para IDs de auditoría
            "CREATE SEQUENCE seq_auditoria START WITH 1 INCREMENT BY 1"
        ]
        
        for table_sql in tables:
            try:
                self.query(table_sql)
                print(f"✓ Tabla/Secuencia creada exitosamente")
            except Exception as e:
                if "ORA-00955" in str(e) or "ORA-02289" in str(e):
                    print(f"⚠ La tabla/secuencia ya existe")
                else:
                    print(f"✗ Error al crear tabla: {e}")
    
    def query(self, sql: str, parameters: Optional[dict] = None) -> Optional[List[Tuple]]:
        """
        Ejecuta una consulta SQL en la base de datos
        
        Args:
            sql: Sentencia SQL a ejecutar
            parameters: Diccionario con parámetros para la consulta
            
        Returns:
            Lista de tuplas con los resultados (solo para SELECT)
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    if parameters:
                        cur.execute(sql, parameters)
                    else:
                        cur.execute(sql)
                    
                    # Si es SELECT, retornar resultados
                    if sql.strip().upper().startswith("SELECT"):
                        resultado = cur.fetchall()
                        return resultado
                    
                    # Para INSERT, UPDATE, DELETE
                    conn.commit()
                    return None
                    
        except oracledb.DatabaseError as e:
            error_obj, = e.args
            print(f"✗ Error en la base de datos:")
            print(f"  Código: {error_obj.code}")
            print(f"  Mensaje: {error_obj.message}")
            raise


class Auditoria:
    """Clase para gestionar la auditoría de consultas del sistema"""
    
    @staticmethod
    def registrar_consulta(db: Database, usuario: str, tipo_consulta: str,
                          indicador_codigo: Optional[str] = None,
                          fecha_solicitada: Optional[str] = None,
                          resultado_exitoso: bool = True,
                          descripcion: Optional[str] = None) -> bool:
        """
        Registra una consulta en la tabla de auditoría
        
        Args:
            db: Instancia de Database
            usuario: Usuario que realiza la consulta
            tipo_consulta: Tipo de operación realizada
            indicador_codigo: Código del indicador consultado (opcional)
            fecha_solicitada: Fecha solicitada en la consulta (opcional)
            resultado_exitoso: Si la consulta fue exitosa
            descripcion: Descripción adicional (opcional)
            
        Returns:
            True si se registró exitosamente, False en caso contrario
        """
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
            
        except Exception as e:
            print(f"⚠ Error al registrar auditoría: {e}")
            return False
    
    @staticmethod
    def obtener_consultas_usuario(db: Database, usuario: str, 
                                  limite: int = 20) -> Optional[List[Tuple]]:
        """
        Obtiene el historial de consultas de un usuario
        
        Args:
            db: Instancia de Database
            usuario: Usuario del cual obtener el historial
            limite: Número máximo de registros a retornar
            
        Returns:
            Lista de tuplas con los registros o None si hay error
        """
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
            
        except Exception as e:
            print(f"✗ Error al obtener consultas: {e}")
            return None
    
    @staticmethod
    def obtener_estadisticas_usuario(db: Database, usuario: str) -> Optional[Dict]:
        """
        Obtiene estadísticas de consultas de un usuario
        
        Args:
            db: Instancia de Database
            usuario: Usuario del cual obtener estadísticas
            
        Returns:
            Diccionario con estadísticas o None si hay error
        """
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
            
        except Exception as e:
            print(f"✗ Error al obtener estadísticas: {e}")
            return None


class Validador:
    """Clase para validar entradas de usuario y prevenir ataques"""
    
    @staticmethod
    def validar_username(username: str) -> Tuple[bool, str]:
        """
        Valida el nombre de usuario
        
        Args:
            username: Nombre de usuario a validar
            
        Returns:
            Tupla (es_valido, mensaje_error)
        """
        if not username or len(username.strip()) == 0:
            return False, "El nombre de usuario no puede estar vacío"
        
        if len(username) < 4:
            return False, "El nombre de usuario debe tener al menos 4 caracteres"
        
        if len(username) > 32:
            return False, "El nombre de usuario no puede exceder 32 caracteres"
        
        # Solo permitir letras, números y guión bajo
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "El nombre de usuario solo puede contener letras, números y guión bajo"
        
        return True, ""
    
    @staticmethod
    def validar_password(password: str) -> Tuple[bool, str]:
        """
        Valida la contraseña según criterios de seguridad
        
        Args:
            password: Contraseña a validar
            
        Returns:
            Tupla (es_valido, mensaje_error)
        """
        if not password or len(password.strip()) == 0:
            return False, "La contraseña no puede estar vacía"
        
        if len(password) < 8:
            return False, "La contraseña debe tener al menos 8 caracteres"
        
        if len(password) > 64:
            return False, "La contraseña no puede exceder 64 caracteres"
        
        # Verificar complejidad
        tiene_mayuscula = any(c.isupper() for c in password)
        tiene_minuscula = any(c.islower() for c in password)
        tiene_numero = any(c.isdigit() for c in password)
        
        if not (tiene_mayuscula and tiene_minuscula and tiene_numero):
            return False, "La contraseña debe contener mayúsculas, minúsculas y números"
        
        return True, ""
    
    @staticmethod
    def validar_fecha(fecha_str: str) -> Tuple[bool, str, Optional[str]]:
        """
        Valida y normaliza formato de fecha
        
        Args:
            fecha_str: Fecha en formato DD-MM-YYYY
            
        Returns:
            Tupla (es_valido, mensaje_error, fecha_normalizada)
        """
        if not fecha_str:
            return True, "", None  # Fecha opcional
        
        # Validar formato
        if not re.match(r'^\d{2}-\d{2}-\d{4}$', fecha_str):
            return False, "Formato de fecha inválido. Use DD-MM-YYYY", None
        
        try:
            partes = fecha_str.split('-')
            dia = int(partes[0])
            mes = int(partes[1])
            anio = int(partes[2])
            
            # Validar rangos
            if not (1 <= mes <= 12):
                return False, "Mes inválido (1-12)", None
            
            if not (1 <= dia <= 31):
                return False, "Día inválido (1-31)", None
            
            if not (2000 <= anio <= 2100):
                return False, "Año fuera de rango (2000-2100)", None
            
            # Intentar crear fecha para validar
            fecha = datetime(anio, mes, dia)
            
            # Normalizar al formato esperado por la API
            fecha_normalizada = fecha.strftime("%d-%m-%Y")
            
            return True, "", fecha_normalizada
            
        except ValueError as e:
            return False, f"Fecha inválida: {e}", None
    
    @staticmethod
    def sanitizar_input(texto: str) -> str:
        """
        Sanitiza entrada de texto para prevenir inyecciones
        
        Args:
            texto: Texto a sanitizar
            
        Returns:
            Texto sanitizado
        """
        # Eliminar caracteres peligrosos
        texto = texto.strip()
        texto = re.sub(r'[;\'"\\<>]', '', texto)
        return texto


class Auth:
    """Clase para gestionar autenticación y autorización de usuarios"""
    
    @staticmethod
    def login(db: Database, username: str, password: str) -> Tuple[bool, str]:
        """
        Realiza el login de un usuario
        
        Args:
            db: Instancia de Database
            username: Nombre de usuario
            password: Contraseña en texto plano
            
        Returns:
            Tupla (exito, mensaje)
        """
        try:
            # Validar entradas
            username = Validador.sanitizar_input(username)
            
            # Buscar usuario
            resultado = db.query(
                sql="SELECT username, password FROM USERS WHERE username = :p_username",
                parameters={"p_username": username}
            )
            
            if not resultado or len(resultado) == 0:
                # Registrar intento fallido
                Auditoria.registrar_consulta(
                    db, username, "LOGIN_FALLIDO", 
                    resultado_exitoso=False,
                    descripcion="Usuario no encontrado"
                )
                return False, "Usuario no encontrado"
            
            # Obtener hash almacenado
            stored_hash = resultado[0][1]
            
            # Convertir de string hex a bytes
            if isinstance(stored_hash, str):
                stored_hash_bytes = bytes.fromhex(stored_hash)
            else:
                stored_hash_bytes = stored_hash
            
            # Verificar contraseña
            password_bytes = password.encode("UTF-8")
            
            if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                # Actualizar último acceso
                db.query(
                    sql="UPDATE USERS SET ultimo_acceso = SYSDATE WHERE username = :p_username",
                    parameters={"p_username": username}
                )
                
                # Registrar login exitoso
                Auditoria.registrar_consulta(
                    db, username, "LOGIN_EXITOSO",
                    resultado_exitoso=True,
                    descripcion="Inicio de sesión correcto"
                )
                
                return True, f"¡Bienvenido {username}!"
            else:
                # Registrar intento fallido
                Auditoria.registrar_consulta(
                    db, username, "LOGIN_FALLIDO",
                    resultado_exitoso=False,
                    descripcion="Contraseña incorrecta"
                )
                return False, "Contraseña incorrecta"
                
        except Exception as e:
            return False, f"Error durante el login: {e}"
    
    @staticmethod
    def register(db: Database, username: str, password: str) -> Tuple[bool, str]:
        """
        Registra un nuevo usuario en el sistema
        
        Args:
            db: Instancia de Database
            username: Nombre de usuario
            password: Contraseña en texto plano
            
        Returns:
            Tupla (exito, mensaje)
        """
        try:
            # Validar username
            es_valido, mensaje = Validador.validar_username(username)
            if not es_valido:
                return False, mensaje
            
            # Validar password
            es_valido, mensaje = Validador.validar_password(password)
            if not es_valido:
                return False, mensaje
            
            # Sanitizar username
            username = Validador.sanitizar_input(username)
            
            # Verificar si el usuario ya existe
            resultado = db.query(
                sql="SELECT username FROM USERS WHERE username = :p_username",
                parameters={"p_username": username}
            )
            
            if resultado and len(resultado) > 0:
                return False, "El nombre de usuario ya está registrado"
            
            # Hashear contraseña
            password_bytes = password.encode("UTF-8")
            salt = bcrypt.gensalt(rounds=12)
            hashed_password = bcrypt.hashpw(password_bytes, salt)
            
            # Convertir hash a string hexadecimal para almacenar
            hash_hex = hashed_password.hex()
            
            # Insertar usuario
            db.query(
                sql="""
                INSERT INTO USERS (id, username, password) 
                VALUES (seq_users.NEXTVAL, :p_username, :p_password)
                """,
                parameters={
                    "p_username": username,
                    "p_password": hash_hex
                }
            )
            
            # Registrar el registro exitoso en auditoría
            Auditoria.registrar_consulta(
                db, username, "REGISTRO_USUARIO",
                resultado_exitoso=True,
                descripcion="Usuario registrado en el sistema"
            )
            
            return True, f"Usuario '{username}' registrado exitosamente"
            
        except Exception as e:
            return False, f"Error durante el registro: {e}"


class IndicadorEconomico:
    """Clase para deserializar datos de indicadores económicos"""
    
    def __init__(self, nombre: str, valor: float, fecha: datetime, 
                 codigo: str, unidad_medida: str):
        """
        Inicializa un indicador económico
        
        Args:
            nombre: Nombre del indicador
            valor: Valor del indicador
            fecha: Fecha del valor
            codigo: Código del indicador
            unidad_medida: Unidad de medida
        """
        self.nombre = nombre
        self.valor = valor
        self.fecha = fecha
        self.codigo = codigo
        self.unidad_medida = unidad_medida
    
    @classmethod
    def from_json(cls, json_data: dict, codigo: str) -> 'IndicadorEconomico':
        """
        Crea una instancia desde datos JSON
        
        Args:
            json_data: Diccionario con datos del indicador
            codigo: Código del indicador solicitado
            
        Returns:
            Instancia de IndicadorEconomico
        """
        try:
            nombre = json_data.get('nombre', codigo.upper())
            unidad_medida = json_data.get('unidad_medida', '')
            
            # Obtener el primer valor de la serie
            serie = json_data.get('serie', [])
            if not serie or len(serie) == 0:
                raise ValueError("No hay datos disponibles en la serie")
            
            primer_dato = serie[0]
            valor = float(primer_dato.get('valor', 0))
            fecha_str = primer_dato.get('fecha', '')
            
            # Parsear fecha
            fecha = datetime.fromisoformat(fecha_str.replace('Z', '+00:00'))
            
            return cls(
                nombre=nombre,
                valor=valor,
                fecha=fecha,
                codigo=codigo,
                unidad_medida=unidad_medida
            )
            
        except Exception as e:
            raise ValueError(f"Error al deserializar indicador: {e}")
    
    def __str__(self) -> str:
        """Representación en string del indicador"""
        fecha_formateada = self.fecha.strftime("%d-%m-%Y")
        return f"{self.nombre}: ${self.valor:,.2f} ({fecha_formateada})"


class Finance:
    """Clase para consultar y gestionar indicadores económicos"""
    
    # Mapeo de indicadores disponibles
    INDICADORES = {
        '1': {'codigo': 'uf', 'nombre': 'Unidad de Fomento (UF)'},
        '2': {'codigo': 'ivp', 'nombre': 'Índice de Valor Promedio (IVP)'},
        '3': {'codigo': 'ipc', 'nombre': 'Índice de Precio al Consumidor (IPC)'},
        '4': {'codigo': 'utm', 'nombre': 'Unidad Tributaria Mensual (UTM)'},
        '5': {'codigo': 'dolar', 'nombre': 'Dólar Observado'},
        '6': {'codigo': 'euro', 'nombre': 'Euro'}
    }
    
    def __init__(self, base_url: str = "https://mindicador.cl/api"):
        """
        Inicializa el cliente de indicadores económicos
        
        Args:
            base_url: URL base de la API
        """
        self.base_url = base_url
    
    def get_indicator(self, codigo_indicador: str, 
                     fecha: Optional[str] = None,
                     db: Optional[Database] = None,
                     usuario: Optional[str] = None) -> Optional[IndicadorEconomico]:
        """
        Obtiene un indicador económico de la API
        
        Args:
            codigo_indicador: Código del indicador (uf, dolar, euro, etc.)
            fecha: Fecha en formato DD-MM-YYYY (opcional)
            db: Instancia de Database para auditoría (opcional)
            usuario: Usuario que realiza la consulta (opcional)
            
        Returns:
            Objeto IndicadorEconomico o None si hay error
        """
        try:
            # Construir URL
            if fecha:
                url = f"{self.base_url}/{codigo_indicador}/{fecha}"
            else:
                url = f"{self.base_url}/{codigo_indicador}"
            
            # Realizar petición
            print(f"Consultando: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Deserializar respuesta
            json_data = response.json()
            indicador = IndicadorEconomico.from_json(json_data, codigo_indicador)
            
            # Registrar consulta exitosa en auditoría
            if db and usuario:
                Auditoria.registrar_consulta(
                    db, usuario, "CONSULTA_INDICADOR",
                    indicador_codigo=codigo_indicador,
                    fecha_solicitada=fecha,
                    resultado_exitoso=True,
                    descripcion=f"Consulta de {indicador.nombre}"
                )
            
            return indicador
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Error en la petición HTTP: {e}")
            
            # Registrar consulta fallida
            if db and usuario:
                Auditoria.registrar_consulta(
                    db, usuario, "CONSULTA_INDICADOR",
                    indicador_codigo=codigo_indicador,
                    fecha_solicitada=fecha,
                    resultado_exitoso=False,
                    descripcion=f"Error HTTP: {str(e)[:200]}"
                )
            
            return None
        except ValueError as e:
            print(f"✗ Error al procesar datos: {e}")
            
            # Registrar consulta fallida
            if db and usuario:
                Auditoria.registrar_consulta(
                    db, usuario, "CONSULTA_INDICADOR",
                    indicador_codigo=codigo_indicador,
                    fecha_solicitada=fecha,
                    resultado_exitoso=False,
                    descripcion=f"Error de datos: {str(e)[:200]}"
                )
            
            return None
        except Exception as e:
            print(f"✗ Error inesperado: {e}")
            
            # Registrar consulta fallida
            if db and usuario:
                Auditoria.registrar_consulta(
                    db, usuario, "CONSULTA_INDICADOR",
                    indicador_codigo=codigo_indicador,
                    fecha_solicitada=fecha,
                    resultado_exitoso=False,
                    descripcion=f"Error: {str(e)[:200]}"
                )
            
            return None
    
    def registrar_indicador(self, db: Database, indicador: IndicadorEconomico,
                           usuario: str) -> Tuple[bool, str]:
        """
        Registra un indicador en la base de datos
        
        Args:
            db: Instancia de Database
            indicador: Objeto IndicadorEconomico a registrar
            usuario: Usuario que realiza la consulta
            
        Returns:
            Tupla (exito, mensaje)
        """
        try:
            sql = """
            INSERT INTO INDICADORES_ECONOMICOS 
            (id, nombre_indicador, valor, fecha_valor, fecha_consulta, 
             usuario_consulta, sitio_proveedor)
            VALUES 
            (seq_indicadores.NEXTVAL, :p_nombre, :p_valor, :p_fecha_valor, 
             SYSDATE, :p_usuario, :p_sitio)
            """
            
            parametros = {
                "p_nombre": indicador.nombre,
                "p_valor": indicador.valor,
                "p_fecha_valor": indicador.fecha,
                "p_usuario": usuario,
                "p_sitio": self.base_url
            }
            
            db.query(sql, parametros)
            
            # Registrar en auditoría
            Auditoria.registrar_consulta(
                db, usuario, "REGISTRO_INDICADOR",
                indicador_codigo=indicador.codigo,
                resultado_exitoso=True,
                descripcion=f"Indicador {indicador.nombre} registrado en BD"
            )
            
            return True, "Indicador registrado exitosamente en la base de datos"
            
        except Exception as e:
            # Registrar fallo en auditoría
            Auditoria.registrar_consulta(
                db, usuario, "REGISTRO_INDICADOR",
                indicador_codigo=indicador.codigo,
                resultado_exitoso=False,
                descripcion=f"Error al registrar: {str(e)[:200]}"
            )
            
            return False, f"Error al registrar indicador: {e}"
    
    @staticmethod
    def mostrar_menu_indicadores() -> None:
        """Muestra el menú de indicadores disponibles"""
        print("\n" + "="*60)
        print("INDICADORES ECONÓMICOS DISPONIBLES")
        print("="*60)
        for key, value in Finance.INDICADORES.items():
            print(f"{key}. {value['nombre']}")
        print("="*60)


def menu_principal():
    """Menú principal del sistema"""
    
    print("\n" + "="*70)
    print("SISTEMA DE GESTIÓN DE EMPLEADOS - ECOTECH SOLUTIONS")
    print("Módulo de Indicadores Económicos")
    print("="*70)
    
    # Inicializar base de datos
    try:
        db = Database(
            username=os.getenv("ORACLE_USER"),
            dsn=os.getenv("ORACLE_DSN"),
            password=os.getenv("ORACLE_PASSWORD")
        )
        print("✓ Conexión a base de datos establecida")
    except Exception as e:
        print(f"✗ Error fatal: No se pudo conectar a la base de datos")
        print(f"  {e}")
        return
    
    # Crear tablas si no existen
    print("\nInicializando tablas...")
    
    # Inicializar módulo de finanzas
    finance = Finance()
    
    # Variables de sesión
    usuario_actual = None
    
    while True:
        print("\n" + "-"*70)
        if usuario_actual:
            print(f"Usuario activo: {usuario_actual}")
        print("-"*70)
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Consultar indicador económico")
        print("4. Consultar y registrar indicador")
        print("5. Ver historial de indicadores")
        print("6. Ver historial de consultas (Auditoría)")
        print("7. Ver estadísticas de uso")
        print("8. Cerrar sesión")
        print("0. Salir")
        print("-"*70)
        
        opcion = input("Seleccione una opción: ").strip()
        
        if opcion == "1":
            # Registro de usuario
            print("\n--- REGISTRO DE NUEVO USUARIO ---")
            username = input("Ingrese nombre de usuario: ").strip()
            password = input("Ingrese contraseña: ").strip()
            
            exito, mensaje = Auth.register(db, username, password)
            if exito:
                print(f"✓ {mensaje}")
            else:
                print(f"✗ {mensaje}")
        
        elif opcion == "2":
            # Login
            print("\n--- INICIO DE SESIÓN ---")
            username = input("Usuario: ").strip()
            password = input("Contraseña: ").strip()
            
            exito, mensaje = Auth.login(db, username, password)
            if exito:
                usuario_actual = username
                print(f"✓ {mensaje}")
            else:
                print(f"✗ {mensaje}")
        
        elif opcion == "3":
            # Consultar indicador (sin registrar)
            if not usuario_actual:
                print("✗ Debe iniciar sesión primero")
                continue
            
            Finance.mostrar_menu_indicadores()
            indicador_opcion = input("\nSeleccione un indicador (1-6): ").strip()
            
            if indicador_opcion not in Finance.INDICADORES:
                print("✗ Opción inválida")
                continue
            
            codigo = Finance.INDICADORES[indicador_opcion]['codigo']
            
            fecha_input = input("Fecha (DD-MM-YYYY) [Enter para hoy]: ").strip()
            
            if fecha_input:
                es_valida, mensaje, fecha_normalizada = Validador.validar_fecha(fecha_input)
                if not es_valida:
                    print(f"✗ {mensaje}")
                    continue
                fecha_input = fecha_normalizada
            
            print("\nConsultando indicador...")
            indicador = finance.get_indicator(codigo, fecha_input, db, usuario_actual)
            
            if indicador:
                print(f"\n✓ {indicador}")
            else:
                print("✗ No se pudo obtener el indicador")
        
        elif opcion == "4":
            # Consultar y registrar indicador
            if not usuario_actual:
                print("✗ Debe iniciar sesión primero")
                continue
            
            Finance.mostrar_menu_indicadores()
            indicador_opcion = input("\nSeleccione un indicador (1-6): ").strip()
            
            if indicador_opcion not in Finance.INDICADORES:
                print("✗ Opción inválida")
                continue
            
            codigo = Finance.INDICADORES[indicador_opcion]['codigo']
            
            fecha_input = input("Fecha (DD-MM-YYYY) [Enter para hoy]: ").strip()
            
            if fecha_input:
                es_valida, mensaje, fecha_normalizada = Validador.validar_fecha(fecha_input)
                if not es_valida:
                    print(f"✗ {mensaje}")
                    continue
                fecha_input = fecha_normalizada
            
            print("\nConsultando indicador...")
            indicador = finance.get_indicator(codigo, fecha_input, db, usuario_actual)
            
            if indicador:
                print(f"\n✓ {indicador}")
                
                registrar = input("\n¿Desea registrar este indicador? (s/n): ").strip().lower()
                if registrar == 's':
                    exito, mensaje = finance.registrar_indicador(db, indicador, usuario_actual)
                    if exito:
                        print(f"✓ {mensaje}")
                    else:
                        print(f"✗ {mensaje}")
            else:
                print("✗ No se pudo obtener el indicador")
        
        elif opcion == "5":
            # Ver historial
            if not usuario_actual:
                print("✗ Debe iniciar sesión primero")
                continue
            
            print("\n--- HISTORIAL DE INDICADORES CONSULTADOS ---")
            
            try:
                resultados = db.query(
                    sql="""
                    SELECT nombre_indicador, valor, 
                           TO_CHAR(fecha_valor, 'DD-MM-YYYY'),
                           TO_CHAR(fecha_consulta, 'DD-MM-YYYY HH24:MI:SS'),
                           usuario_consulta
                    FROM INDICADORES_ECONOMICOS
                    WHERE usuario_consulta = :p_usuario
                    ORDER BY fecha_consulta DESC
                    """,
                    parameters={"p_usuario": usuario_actual}
                )
                
                if resultados and len(resultados) > 0:
                    print(f"\nTotal de registros: {len(resultados)}\n")
                    for i, fila in enumerate(resultados, 1):
                        print(f"{i}. {fila[0]}")
                        print(f"   Valor: ${fila[1]:,.2f}")
                        print(f"   Fecha del indicador: {fila[2]}")
                        print(f"   Fecha de consulta: {fila[3]}")
                        print()
                else:
                    print("No hay registros de indicadores consultados")
                    
            except Exception as e:
                print(f"✗ Error al consultar historial: {e}")
        
        elif opcion == "6":
            # Ver historial de auditoría
            if not usuario_actual:
                print("✗ Debe iniciar sesión primero")
                continue
            
            print("\n--- HISTORIAL DE CONSULTAS (AUDITORÍA) ---")
            
            resultados = Auditoria.obtener_consultas_usuario(db, usuario_actual, limite=30)
            
            if resultados and len(resultados) > 0:
                print(f"\nÚltimas {len(resultados)} consultas:\n")
                for i, fila in enumerate(resultados, 1):
                    tipo_consulta = fila[0]
                    indicador = fila[1] or "N/A"
                    fecha_solicitada = fila[2] or "N/A"
                    fecha_hora = fila[3]
                    exitoso = "✓" if fila[4] == 'S' else "✗"
                    descripcion = fila[5] or ""
                    
                    print(f"{i}. [{exitoso}] {tipo_consulta}")
                    print(f"   Fecha/Hora: {fecha_hora}")
                    if indicador != "N/A":
                        print(f"   Indicador: {indicador}")
                    if fecha_solicitada != "N/A":
                        print(f"   Fecha solicitada: {fecha_solicitada}")
                    if descripcion:
                        print(f"   Descripción: {descripcion}")
                    print()
            else:
                print("No hay consultas registradas")
        
        elif opcion == "7":
            # Ver estadísticas
            if not usuario_actual:
                print("✗ Debe iniciar sesión primero")
                continue
            
            print("\n--- ESTADÍSTICAS DE USO ---")
            
            stats = Auditoria.obtener_estadisticas_usuario(db, usuario_actual)
            
            if stats:
                print(f"\nTotal de consultas: {stats['total_consultas']}")
                print(f"Consultas exitosas: {stats['exitosas']}")
                print(f"Consultas fallidas: {stats['fallidas']}")
                
                if stats['total_consultas'] > 0:
                    tasa_exito = (stats['exitosas'] / stats['total_consultas']) * 100
                    print(f"Tasa de éxito: {tasa_exito:.1f}%")
                
                print(f"Indicadores distintos consultados: {stats['indicadores_distintos']}")
                print(f"Primera consulta: {stats['primera_consulta']}")
                print(f"Última consulta: {stats['ultima_consulta']}")
            else:
                print("No hay estadísticas disponibles")
        
        elif opcion == "8":
            # Cerrar sesión
            if usuario_actual:
                # Registrar cierre de sesión
                Auditoria.registrar_consulta(
                    db, usuario_actual, "LOGOUT",
                    resultado_exitoso=True,
                    descripcion="Cierre de sesión"
                )
                print(f"✓ Sesión cerrada para {usuario_actual}")
                usuario_actual = None
            else:
                print("✗ No hay sesión activa")
        
        elif opcion == "0":
            # Salir
            if usuario_actual:
                Auditoria.registrar_consulta(
                    db, usuario_actual, "LOGOUT",
                    resultado_exitoso=True,
                    descripcion="Salida del sistema"
                )
            print("\n¡Gracias por usar el sistema!")
            print("="*70)
            break
        
        else:
            print("✗ Opción inválida")


if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print("\n\n✓ Programa interrumpido por el usuario")
    except Exception as e:
        print(f"\n✗ Error fatal: {e}")
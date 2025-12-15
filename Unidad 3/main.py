import bcrypt
import requests
import oracledb
import os
from dotenv import load_dotenv
from typing import Optional
import datetime

load_dotenv()

class Database:
    def __init__(self, username, dsn, password):
        self.username = username
        self.dsn = dsn
        self.password = password
    def get_connection(self):
        return oracledb.connect(user=self.username, password=self.password, dsn=self.dsn)
    def create_all_tables(self):
        tables = [
            (
                "CREATE TABLE USERS("
                "id INTEGER PRIMARY KEY,"
                "username VARCHAR(32) UNIQUE,"
                "password VARCHAR(128)"
                ")"
            )
        ]

        for table in tables:
            self.query(table)

    def query(self, sql: str, parameters: Optional[dict] = None):
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    ejecucion = cur.execute(sql, parameters)
                    if sql.startswith("SELECT"):
                        resultado = []
                        for fila in ejecucion:
                            resultado.append(fila)
                        return resultado
                conn.commit()
        except oracledb.DatabaseError as error:
            print(error)

class Auth:
    @staticmethod
    def login(db: Database, username: str, password: str):
        password = password.encode("UTF-8")

        resultado = db.query(
            sql= "SELECT * FROM USERS WHERE username = :username",
            parameters={"username":username}
        )

        if len(resultado) < 0:
            return print("No hay coincidencias")
        
        hashed_password = bytes.fromhex(resultado[0][2])

        if bcrypt.checkpw(password, hashed_password):
            return print("Logeado correctamente")
        else:
            return print("Contraseña incorrecta")

    @staticmethod
    def register(db: Database, id: int, username: str, password: str):
        print("registrando usuario")
        password = password.encode("UTF-8")
        salt = bcrypt.gensalt(12)
        hash_password = bcrypt.hashpw(password,salt)

        usuario = {
            "id": id,
            "username": username,
            "password": hash_password
        }

        db.query(
            sql= "INSERT INTO USERS(id,username,password) VALUES (:id, :username, :password)",
            parameters=usuario
        )
        print("usuario registrado con exito")

class Finance:
    def __init__(self, base_url: str = "https://mindicador.cl/api"):
        self.base_url = base_url
    def get_indicator(self, indicator: str, fecha: str = None) -> float:
        try:
            if not fecha:
                dd = datetime.datetime.now().day
                mm = datetime.datetime.now().month
                yyyy = datetime.datetime.now().year
                fecha = f"{dd}-{mm}-{yyyy}"
            url = f"{self.base_url}/{indicator}/{fecha}"
            respuesta = requests.get(url).json()
            return respuesta["serie"][0]["valor"]
        except:
            print("Hubo un error con la solicitud")
    def get_usd(self, fecha: str = None):
        valor = self.get_indicator("dolar", fecha)
        print(f"El valor del dolar en CLP es: {valor}")
    def get_eur(self, fecha: str = None):
        self.get_indicator("euro", fecha)
    def get_uf(self, fecha: str = None):
        self.get_indicator("uf", fecha)
    def get_ivp(self, fecha: str = None):
        self.get_indicator("ivp", fecha)
    def get_ipc(self, fecha: str = None):
        self.get_indicator("ipc", fecha)
    def get_utm(self, fecha: str = None):
        self.get_indicator("utm", fecha)

if __name__ == "__main__":
    db = Database(
        username=os.getenv("ORACLE_USER"),
        password=os.getenv("ORACLE_PASSWORD"),
        dsn=os.getenv("ORACLE_DSN")
    )

    Auth.login(db,"soyelseba","alskjflsakf")
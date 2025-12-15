"""
API:
Application Programming Interface
Es una "Interfaz" o "Mesero Digital" que me permite
comunicarme entre aplicaciones para acceder a información
o gestionarla.


HTTP:
HyperText Transfer Protocol
Protocolo de transferencia por excelencia a través
del internet para comunicarse entre aplicaciones.

HEAD: Información adicional importante 
-> Con que tipo de informacion voy a trabajar
    Content-Type: application/json
-> Si tengo que autenticame, cómo lo voy a hacer
    Authorization: secreto


BODY: Información principal de comunicación

URL: La úbicación a dónde voy a ir a buscar la información
STATUS: Estado de respuesta de la solicitud

Flujo de solicitud
1. (Nosotros)Python -[Solicitud]-> API
2. API -[Respuesta]-> (Nosotros)Python


Estructura de úbicación

[Declarar el protocolo]
↓
https://universalis.app/api/v2/data-centers
              ↑         ↑
[Dónde está la API]     [El recurso o endpoint]

SERIALIZACION DE LA INFORMACION
Utilizar un estandar de ordenar la información que quiero
comunicar, para ello, utilizo serializadores cómo:

- JSON (Javascript Object Notation)
    { "persona" : { "id" : 1092, "nombre": "Sebastian" }}

- XML (Extensible Markup Language)
    
    <persona>
        <id>1092</id>
        <nombre>Sebastian</nombre>
    </persona>
"""

import requests

respuesta = requests.get(url="https://universalis.app/api/v2/data-centers")
codigo_respuesta = respuesta.status_code
data = respuesta.json()

print(data)
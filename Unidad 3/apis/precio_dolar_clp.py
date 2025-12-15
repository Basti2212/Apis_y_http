import requests
base_url = "https://cl.dolarapi.com"
respuesta = requests.get(url=f"{base_url}/v1/cotizaciones/usd")
codigo_respuesta = respuesta.status_code
try: 
    data = respuesta.json()
    print(f"El valor del dolar contrastado con el peso chileno está en: {data["ultimoCierre"]} CLP")
except:
    print(respuesta)
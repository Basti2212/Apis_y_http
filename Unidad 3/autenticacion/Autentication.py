"""La autenticación de usuarios en el sistema"""

"""
La autenticación actúa como un punto de control crucial, 
garantizando que solo los usuarios autorizados puedan acceder a ciertos recursos web
"""

"""
Métodos Comunes de Autenticación:
- Básica (Basic Auth): Envía credenciales codificadas en Base64 en el encabezado HTTP.
- Token Bearer: Usa tokens (como JWT) en el encabezado Authorization.
- OAuth2: Protocolo estándar para autorización delegada, común en APIs.
- API Keys: Claves únicas proporcionadas en solicitudes para identificar al cliente.
- Autenticación basada en formularios: Usuarios ingresan credenciales en un formulario web.
"""

"""
Consideraciones de Seguridad:
- Siempre usar HTTPS para proteger credenciales en tránsito.
- Almacenar contraseñas de forma segura (hashing + salting).
- Implementar mecanismos de bloqueo tras múltiples intentos fallidos.
"""

"""
Autenticación vs. Autorización: La autenticación confirma quién eres (credenciales),
mientras que la autorización verifica qué puedes hacer (permisos).
Tokens: Se suele obtener un "token de acceso" tras autenticarse,
que se usa en llamadas posteriores a la API, con una vida útil limitada (horas).
"""

"""
Autenticación Basada en Usuario/Contraseña:
Se proveen credenciales (usuario/contraseña) al instanciar un cliente o al hacer una solicitud.
El servidor las verifica contra una base de datos (o proveedor de identidad).
Se puede implementar manualmente validando entradas o usando frameworks.
"""
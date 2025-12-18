""" Que es un hash y como se utiliza en autenticación de usuarios """

"""
El hashing en Python es un proceso que convierte datos de entrada (texto, archivos) en una cadena de bytes de longitud fija, 
llamada hash, usando una función matemática. 
Funciona de manera unidireccional (difícil de revertir) y determinista (siempre el mismo input da el mismo hash).
Se usa para verificar integridad de datos, almacenar contraseñas de forma segura y en firmas digitales.
"""

"""
Como se utiliza en autenticación de usuarios:
Almacena contraseñas de forma segura: En lugar de guardar contraseñas en texto plano, se almacena su hash. 
Cuando un usuario ingresa su contraseña, se calcula el hash y se compara con el almacenado.
Verifica integridad de datos: Se usa para asegurar que los datos no han sido alterados durante la transmisión o almacenamiento.
En firmas digitales: Se emplea para crear firmas digitales que verifican la autenticidad de documentos o mensajes.
"""

"""
Bibliotecas comunes en Python para hashing:
- hashlib: Proporciona funciones de hashing como SHA-256, SHA-1, MD5.
- bcrypt: Diseñada específicamente para almacenar contraseñas de forma segura.
- passlib: Ofrece una variedad de algoritmos de hashing y es fácil de usar para la gestión de contraseñas.
- scrypt: Algoritmo de hashing resistente a ataques de fuerza bruta, adecuado para contraseñas.
"""

"""
Consideraciones de seguridad:
- Usar funciones de hashing seguras y actualizadas (evitar MD5, SHA-1).
- Implementar salting (agregar datos aleatorios a la contraseña antes de hashear) para proteger contra ataques de rainbow table.
- Utilizar algoritmos de hashing adaptativos (como bcrypt, Argon2) que pueden ajustarse para ser más lentos con el tiempo, dificultando ataques de fuerza bruta.
- Mantener las bibliotecas de hashing actualizadas para beneficiarse de mejoras y correcciones de seguridad.
"""
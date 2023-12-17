from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

def generar_claves_rsa(tamano_clave=2048):
    # Generar la clave privada
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamano_clave,
        backend=default_backend()
    )

    # Obtener la clave pública a partir de la clave privada
    clave_publica = clave_privada.public_key()

    # Serializar la clave privada para guardarla en un archivo
    clave_privada_serializada = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar la clave pública para guardarla en un archivo
    clave_publica_serializada = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return clave_publica_serializada, clave_privada_serializada

# Guardar las claves RSA generadas en archivos PEM
def guardar_claves_en_archivos(clave_publica, clave_privada, archivo_publico, archivo_privado):
    # Guardar la clave pública en un archivo PEM
    with open(archivo_publico, 'wb') as f_publico:
        f_publico.write(clave_publica)

    # Guardar la clave privada en un archivo PEM
    with open(archivo_privado, 'wb') as f_privado:
        f_privado.write(clave_privada)

    return "Claves guardadas con éxito"

def leer_clave_publica_rsa(archivo_publico):
    with open(archivo_publico, 'rb') as archivo:
        clave_publica = load_pem_public_key(archivo.read(), backend=default_backend())
    return clave_publica

def leer_clave_privada_rsa(archivo_privado, password=None):
    with open(archivo_privado, 'rb') as archivo:
        clave_privada = load_pem_private_key(archivo.read(), password=password, backend=default_backend())
    return clave_privada



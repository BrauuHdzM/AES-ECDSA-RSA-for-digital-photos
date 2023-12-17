from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

#Generación de claves ECDSA
def generar_par_claves(curva = ec.SECP224R1()):
    clave_privada = ec.generate_private_key(curva, default_backend())
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

#Guardar claves en archivo PEM
def guardar_clave_privada_en_archivo(clave, nombre_archivo):
    with open(nombre_archivo, 'wb') as archivo_clave:
        datos_clave = clave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        archivo_clave.write(datos_clave)

def guardar_clave_publica_en_archivo(clave, nombre_archivo):
    with open(nombre_archivo, 'wb') as archivo_clave:
        datos_clave = clave.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        archivo_clave.write(datos_clave)

#Cargar claves desde archivo PEM
def cargar_clave_desde_archivo(nombre_archivo):
    with open(nombre_archivo, 'rb') as archivo_clave:
        datos_clave = archivo_clave.read()
        clave = serialization.load_pem_private_key(datos_clave, password=None, backend=default_backend())
        return clave

def cargar_clave_publica_desde_archivo(nombre_archivo):
    with open(nombre_archivo, 'rb') as archivo_clave:
        datos_clave = archivo_clave.read()
        clave = serialization.load_pem_public_key(datos_clave, backend=default_backend())
        return clave
    
#Firmar documento
def firmar_documento(clave_privada, ruta_documento):
    with open(ruta_documento, 'rb') as archivo_documento:
        datos_documento = archivo_documento.read()
        firma = clave_privada.sign(datos_documento, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(firma)

#Verificar firma de documento
def verificar_firma(clave_publica, ruta_documento, firma):
    with open(ruta_documento, 'rb') as archivo_documento:
        datos_documento = archivo_documento.read()
        try:
            #firma = base64.b64decode(firma)
            clave_publica.verify(firma, datos_documento, ec.ECDSA(hashes.SHA256()))
            print("Firma válida")
            return True
        except Exception as e:
            print(f"Error de verificación: {e}")
            return False

#Guardar firma en un archivo
def guardar_firma_en_archivo(firma, nombre_archivo):
    with open(nombre_archivo, 'w') as archivo_firma:
        archivo_firma.write(firma.decode('utf-8'))

# Leer firma desde un archivo y decodificarla de Base64
def leer_firma_desde_archivo(nombre_archivo):
    with open(nombre_archivo, 'rb') as archivo_firma:
        firma_base64 = archivo_firma.read()
        return base64.b64decode(firma_base64)


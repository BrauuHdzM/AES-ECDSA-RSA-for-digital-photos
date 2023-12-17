from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from PIL import Image
import io
import secrets

def cifrar_archivo_aes_gcm(imagen_original, archivo_cifrado, clave_publica_rsa):
    # Leer y convertir la imagen en datos binarios
    with Image.open(imagen_original) as img:
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        datos_imagen = buffer.getvalue()

    # Generar clave AES aleatoria
    clave_aes = secrets.token_bytes(32)

    # Cargar la clave pública
    with open(clave_publica_rsa, 'rb') as archivo_clave_publica:
        clave_publica = serialization.load_pem_public_key(
            archivo_clave_publica.read(), backend=default_backend()
        )

    # Cifrar la clave AES
    clave_aes_cifrada = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Cifrar los datos de la imagen
    iv = secrets.token_bytes(16)
    cifrador = Cipher(algorithms.AES(clave_aes), modes.GCM(iv), backend=default_backend()).encryptor()

    datos_cifrados = cifrador.update(datos_imagen)

    cifrador.finalize()

    # Escribir los datos cifrados en un archivo
    with open(archivo_cifrado, 'wb') as archivo_out:
        archivo_out.write(clave_aes_cifrada)
        print(len(clave_aes_cifrada))
        archivo_out.write(iv)
        print(len(iv))
        archivo_out.write(datos_cifrados)
        print(len(datos_cifrados))
        archivo_out.write(cifrador.tag)
        print(len(cifrador.tag))
        

def descifrar_archivo_aes_gcm(archivo_cifrado, imagen_descifrada_ruta, clave_privada_rsa):
    
    with open(archivo_cifrado, 'rb') as archivo_in:
        # Leer la longitud total del archivo
        archivo_in.seek(0, io.SEEK_END)
        longitud_total = archivo_in.tell()

        # Calcular la longitud de los datos cifrados
        longitud_clave_aes_cifrada = 256  # Ajustar según el tamaño de la clave RSA
        longitud_iv = 16
        longitud_tag = 16
        longitud_datos_cifrados = longitud_total - longitud_clave_aes_cifrada - longitud_iv - longitud_tag

        # Retroceder al principio del archivo y leer los componentes
        archivo_in.seek(0)
        clave_aes_cifrada = archivo_in.read(longitud_clave_aes_cifrada)
        iv = archivo_in.read(longitud_iv)
        datos_cifrados = archivo_in.read(longitud_datos_cifrados)
        tag = archivo_in.read(longitud_tag)

    # Cargar la clave privada
    with open(clave_privada_rsa, 'rb') as archivo_clave_privada:
        clave_privada = serialization.load_pem_private_key(
            archivo_clave_privada.read(), password=None, backend=default_backend()
        )

    # Descifrar la clave AES
    clave_aes = clave_privada.decrypt(
        clave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Descifrar los datos de la imagen
    descifrador = Cipher(algorithms.AES(clave_aes), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    datos_descifrados = descifrador.update(datos_cifrados)
    try:
        descifrador.finalize()
        # Verificar si la ruta de imagen descifrada tiene una extensión de archivo válida
        if not imagen_descifrada_ruta.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            raise ValueError("La ruta de la imagen descifrada debe tener una extensión de archivo válida.")
        # Convertir los datos descifrados en una imagen y guardarla
        imagen_descifrada = Image.open(io.BytesIO(datos_descifrados))
        imagen_descifrada.save(imagen_descifrada_ruta)
        print("El archivo ha sido descifrado con éxito.")
    except Exception as e:
        print("Error durante el descifrado:", e)


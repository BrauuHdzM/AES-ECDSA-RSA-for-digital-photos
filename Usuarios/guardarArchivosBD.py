import firebase_admin
from firebase_admin import credentials, storage

def initialize_firebase():
    #"""Inicializa la aplicación Firebase si aún no está inicializada."""
    if not firebase_admin._apps:
        # Ruta al archivo de credenciales JSON de Firebase
        cred = credentials.Certificate("C:/Users/Alex Olivares/Downloads/Proyecto-Criptografia/proyectocriptografia-724c1-firebase-adminsdk-bo6u7-6ab1f565fc.json")
        firebase_admin.initialize_app(cred)

def upload_to_storage(source_file_name, destination_folder, destination_file_name):
    #"""Sube un archivo al bucket predeterminado de Cloud Storage en una carpeta específica."""
    # Inicializar Firebase
    initialize_firebase()
    
    # Obtener el bucket predeterminado
    bucket = firebase_admin.storage.bucket(name="proyectocriptografia-724c1.appspot.com")

    # Ruta completa del archivo en el bucket, incluyendo la carpeta
    destination_blob_name = f"{destination_folder}/{destination_file_name}"

    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(source_file_name)

    print(f"Archivo {source_file_name} subido a {destination_blob_name}.")

def download_from_storage(destination_folder, file_name, local_destination):
    #"""Descarga un archivo desde Cloud Storage a una ubicación local."""
    # Inicializar Firebase
    initialize_firebase()

    bucket = firebase_admin.storage.bucket(name="proyectocriptografia-724c1.appspot.com")

    # Ruta completa del archivo en el bucket
    blob_name = f"{destination_folder}/{file_name}"

    # Crear una instancia del blob
    blob = bucket.blob(blob_name)

    # Descargar el archivo
    blob.download_to_filename(local_destination)
    print(f"Archivo {file_name} descargado a {local_destination}.")

# Ejemplo de uso
source_file_name = "C:/Users/Alex Olivares/Downloads/Proyecto-Criptografia/clave_privada_braulio.pem"
destination_folder = "llaves_publicas_ECDSA"
destination_file_name = "clave_publica_braulio.pem"

upload_to_storage(source_file_name, destination_folder, destination_file_name)

# Ejemplo de uso
destination_folder = "llaves_publicas_ECDSA"
file_name = "clave_publica_braulio.pem"
local_destination = "descargaArchivo.pem"

#download_from_storage(destination_folder, file_name, local_destination)



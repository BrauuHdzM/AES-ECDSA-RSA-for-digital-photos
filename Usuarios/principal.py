import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import AES
import ECDSA
import RSA
import firebase_admin
from firebase_admin import credentials, storage

# Funciones para subir y descargar archivos de Firebase Storage
def initialize_firebase():
    #"""Inicializa la aplicación Firebase si aún no está inicializada."""
    if not firebase_admin._apps:
        # Ruta al archivo de credenciales JSON de Firebase
        cred = credentials.Certificate("proyectocriptografia-724c1-firebase-adminsdk-bo6u7-6ab1f565fc.json")
        firebase_admin.initialize_app(cred)

def upload_to_storage(source_file_name, destination_folder, destination_file_name):
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

#GENERACION DE PAR DE LLAVES ECDSA
def ECDSAGen(nombre):
    clave_privada, clave_publica = ECDSA.generar_par_claves()
    ECDSA.guardar_clave_privada_en_archivo(clave_privada, f'clave_privada_{nombre}.pem')
    ECDSA.guardar_clave_publica_en_archivo(clave_publica, f'clave_publica_{nombre}.pem')

    #Subida
    source_file_name = f'clave_publica_{nombre}.pem'
    destination_folder = "llaves_publicas_ECDSA"
    destination_file_name = source_file_name
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def RSAGen():
    clave_publica_RSA, clave_privada_RSA = RSA.generar_claves_rsa()
    RSA.guardar_claves_en_archivos(clave_publica_RSA, clave_privada_RSA, f'clave_publica_RSA_{nombre}.pem', f'clave_privada_RSA_{nombre}.pem')

    #Subida 
    source_file_name = f'clave_publica_RSA_{nombre}.pem'
    destination_folder = "llaves_publicas_RSA"
    destination_file_name = source_file_name
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def AESCip(ruta_archivo_original, ruta_archivo_cifrado, ruta_clave):
    print("\n")
    print(f'El archivo original es {ruta_archivo_original}')
    print(f'El archivo cifrado se guardara con el nombre {ruta_archivo_cifrado}')
    print(f'La clave a utilizar es {ruta_clave}')
    print("\n")
    AES.cifrar_archivo_aes_gcm(ruta_archivo_original, ruta_archivo_cifrado, ruta_clave)
    
    #Subida
    source_file_name = ruta_archivo_cifrado
    destination_folder = "archivos_cifrados_usuarios"
    destination_file_name = source_file_name
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def AESDec(file_name, local_destination, clave_privada_RSA, nombrebajada):
    #Descarga de archivo cifrado
    destination_folder = "archivos_cifrados_usuarios"
    download_from_storage(destination_folder, file_name, local_destination)

    ruta_archivo_cifrado = local_destination
    ruta_archivo_descifrado = nombrebajada + '.png'
    print("\n")
    print(f'El archivo cifrado es {ruta_archivo_cifrado}')
    print(f'El archivo descifrado se guardara con el nombre {ruta_archivo_descifrado}')
    print(f'La clave a utilizar es {clave_privada_RSA}')
    print("\n")
    AES.descifrar_archivo_aes_gcm(ruta_archivo_cifrado, ruta_archivo_descifrado, clave_privada_RSA)

def firmarCifrado(clave_privada, ruta_documento, ruta_documento_firmado):
    firma = ECDSA.firmar_documento(clave_privada, ruta_documento)
    ECDSA.guardar_firma_en_archivo(firma, ruta_documento_firmado)
    #Subida
    source_file_name = ruta_documento_firmado
    destination_folder = "archivos_firmados_usuarios"
    destination_file_name = source_file_name
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def verificarFirma(ruta_archivo, ruta, clave_publica_ingreso):
    clave_publica = ECDSA.cargar_clave_publica_desde_archivo(clave_publica_ingreso)
    # Leer la firma desde el archivo
    firma_leida = ECDSA.leer_firma_desde_archivo(ruta)

    # Verificar la firma
    resultado_verificacion = ECDSA.verificar_firma(clave_publica, ruta_archivo, firma_leida)

##Crear pares de claves
nombre = input("Ingresa tu nombre: ")
ECDSAGen(nombre)
RSAGen()

##Cifrado
ruta_archivo_original = input("Ingresa la ruta del archivo a cifrar: ")
ruta_archivo_cifrado = input("Ingresa la ruta del archivo cifrado: ")
download_from_storage("llaves_publicas_RSA","clave_publica_RSA_administrador.pem","clave_publica_RSA_administrador.pem")
AESCip(ruta_archivo_original, ruta_archivo_cifrado, "clave_publica_RSA_administrador.pem")

##Firmado
clave_privada_ECDSA_ruta = input("Ingresa la ruta de la clave privada ECDSA de quien firma: ")
clave_privada_ECDSA = ECDSA.cargar_clave_desde_archivo(clave_privada_ECDSA_ruta)
ruta_documento = input("Ingresa el nombre para guardar el documento firmado: ")
firmarCifrado(clave_privada_ECDSA, ruta_archivo_cifrado, ruta_documento)

##Descifrado
file_name = input("Ingresa el nombre del archivo a descargar: ")
local_destination = input("Ingresa la ruta a guardar el archivo: ")
clave_privada_RSA = input("Ingresa la ruta de la clave privada RSA de quien descifra: ")
nombrebajada = input("Ingresa el nombre del archivo a guardar: ")
AESDec(file_name, local_destination, clave_privada_RSA, nombrebajada)

##Verificar firma
ruta_archivo = input("Ruta del documento a verificar: ")
ruta = input("Ruta de la firma: ")
clave_publica_ingreso = input("Ruta de la llave pública: ")
download_from_storage("archivos_firmados_usuarios", ruta, ruta + "admin.sig")
ruta_descargada = ruta + "admin.sig"
print(f'El archivo es: {ruta_archivo}')
print(f'La firma es: {ruta}')
print(f'La clave pública es: {clave_publica_ingreso}')
verificarFirma(ruta_archivo, ruta_descargada, clave_publica_ingreso)


import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Toplevel, Listbox
from tkinter import simpledialog
import threading
import AES
import ECDSA
import RSA
import firebase_admin
from firebase_admin import credentials, storage
from google.cloud import storage
from google.cloud.exceptions import NotFound

if len(sys.argv) > 2:
    nombre = sys.argv[1]
    usuario = sys.argv[2]
    print(f"¡Bienvenido, {nombre}! Tu nombre de usuario es {usuario}.")

# Funciones
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
    # Inicializar Firebase
    initialize_firebase()

    bucket = firebase_admin.storage.bucket(name="proyectocriptografia-724c1.appspot.com")

    # Asegúrate de que la ruta del archivo se construya correctamente
    # Si 'file_name' ya contiene parte de la ruta, no agregues 'destination_folder' nuevamente
    if not file_name.startswith(destination_folder):
        file_name = f"{destination_folder}/{file_name}"

    # Crear una instancia del blob
    blob = bucket.blob(file_name)

    # Intentar descargar el archivo
    try:
        blob.download_to_filename(local_destination)
        print(f"Archivo {file_name} descargado a {local_destination}.")
    except NotFound:
        print(f"Error: El archivo {file_name} no se encontró en Firebase Storage.")


def list_files_in_storage(destination_folder):
    initialize_firebase()
    bucket = firebase_admin.storage.bucket(name="proyectocriptografia-724c1.appspot.com")
    blobs = bucket.list_blobs(prefix=destination_folder + "/")
    return [blob.name for blob in blobs]

#GENERACION DE PAR DE LLAVES ECDSA
def ECDSAGen(nombre):
    clave_privada, clave_publica = ECDSA.generar_par_claves()
    ECDSA.guardar_clave_privada_en_archivo(clave_privada, f'clavesECDSA/clave_privada_{nombre}.pem')
    ECDSA.guardar_clave_publica_en_archivo(clave_publica, f'clavesECDSA/clave_publica_{nombre}.pem')

    #Subida
    source_file_name = f'clavesECDSA/clave_publica_{nombre}.pem'
    destination_folder = "llaves_publicas_ECDSA"
    destination_file_name=  source_file_name.replace('clavesECDSA', "").strip("/")
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def RSAGen(nombre):
    clave_publica_RSA, clave_privada_RSA = RSA.generar_claves_rsa()
    RSA.guardar_claves_en_archivos(clave_publica_RSA, clave_privada_RSA, f'clavesRSA/clave_publica_RSA_{nombre}.pem', f'clavesRSA/clave_privada_RSA_{nombre}.pem')

    #Subida 
    source_file_name = f'clavesRSA/clave_publica_RSA_{nombre}.pem'
    destination_folder = "llaves_publicas_RSA"
    destination_file_name=  source_file_name.replace('clavesRSA', "").strip("/")
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def AESCip(ruta_archivo_original, ruta_archivo_cifrado, ruta_clave, nombre):
    print("\n")
    print(f'El archivo original es {ruta_archivo_original}')
    print(f'El archivo cifrado se guardara con el nombre {ruta_archivo_cifrado}')
    print(f'La clave a utilizar es {ruta_clave}')
    print("\n")
    
    AES.cifrar_archivo_aes_gcm(ruta_archivo_original, ruta_archivo_cifrado, ruta_clave)
    
    #Subida
    source_file_name = ruta_archivo_cifrado
    destination_folder = "archivos_cifrados_administrador"
    destination_file_name = f'imagenArteCifrada{nombre}.enc'
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def AESDec(file_name, local_destination, clave_privada_RSA, nombrebajada):
    #Descarga de archivo cifrado
    destination_folder = "archivos_cifrados_usuarios"
    local_destination = f'archivosCifrados/{local_destination}.enc'
    file_name =  file_name.replace(destination_folder, "").strip("/")
    download_from_storage(destination_folder, file_name, local_destination)

    ruta_archivo_cifrado = local_destination
    ruta_archivo_descifrado = f'imagenesDescifradas/{nombrebajada}.jpg'
    print("\n")
    print(f'El archivo cifrado es {ruta_archivo_cifrado}')
    print(f'El archivo descifrado se guardara con el nombre {ruta_archivo_descifrado}')
    print(f'La clave a utilizar es {clave_privada_RSA}')
    print("\n")
    AES.descifrar_archivo_aes_gcm(ruta_archivo_cifrado, ruta_archivo_descifrado, clave_privada_RSA)

def firmarCifrado(clave_privada, ruta_documento, ruta_documento_firmado, nombre):
    firma = ECDSA.firmar_documento(clave_privada, ruta_documento)
    ECDSA.guardar_firma_en_archivo(firma, ruta_documento_firmado)
    #Subida
    source_file_name = ruta_documento_firmado
    destination_folder = "archivos_firmados_administrador"
    destination_file_name = f'firmaDigitalArte{nombre}.sig'
    upload_to_storage(source_file_name, destination_folder, destination_file_name)

def verificarFirma(ruta_archivo, ruta, clave_publica_ingreso):
    destination_folder = "llaves_publicas_ECDSA"
    local_destination = f'clavesECDSA/usuarios/clave_publica_{clave_publica_ingreso}.pem'
    file_name =  destination_folder + "/" + f'clave_publica_{clave_publica_ingreso}.pem'
    download_from_storage(destination_folder, file_name, local_destination)
    clave_publica = ECDSA.cargar_clave_publica_desde_archivo(local_destination)
    # Leer la firma desde el archivo
    firma_leida = ECDSA.leer_firma_desde_archivo(ruta)

    # Verificar la firma
    resultado_verificacion = ECDSA.verificar_firma(clave_publica, ruta_archivo, firma_leida)
    if resultado_verificacion:
        return True
    else:
        return False

def download_file_from_storage(file_category, file_name, local_destination):
    initialize_firebase()

    bucket = firebase_admin.storage.bucket(name="proyectocriptografia-724c1.appspot.com")

    # Construir la ruta del archivo en el bucket
    blob_name = f"{file_category}/{file_name}"

    blob = bucket.blob(blob_name)

    try:
        blob.download_to_filename(local_destination)
        print(f"Archivo {file_name} descargado a {local_destination}.")
    except NotFound:
        print(f"Error: El archivo {file_name} no se encontró en Firebase Storage.")


# Interfaz Gráfica
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Configurar estilo y geometría de la ventana
        self.title(f"Bienvenido Administrador {nombre}")
        self.geometry("600x400")
        self.configure(bg='white')

        # Título y bienvenida personalizados
        titulo = ttk.Label(self, text=f"Bienvenido {nombre}", font=('Helvetica', 16, 'bold'), background='white')
        titulo.pack(pady=(10, 2))
        subtitulo = ttk.Label(self, text=f"Tu nombre de usuario es: {usuario}", background='white')
        subtitulo.pack(pady=(0, 20))

        # Texto de advertencia
        texto_advertencia = ttk.Label(self, text="Recuerda, si perdiste alguna de tus llaves, contacta al programador.", background='white', wraplength=500)
        texto_advertencia.pack(pady=(10, 5))

        # Botones y acciones
        ttk.Button(self, text="Generar Par de Claves ECDSA", command=self.generate_ecdsa_keys, style='TButton').pack(pady=5, ipadx=10, ipady=5)
        ttk.Button(self, text="Generar Par de Claves RSA", command=self.generate_rsa_keys, style='TButton').pack(pady=5, ipadx=10, ipady=5)
        ttk.Button(self, text="Cifrar y firmar archivo", command=self.encrypt_sign_file, style='TButton').pack(pady=5, ipadx=10, ipady=5)
        ttk.Button(self, text="Descifrar y verificar archivo", command=self.decrypt_verify_file, style='TButton').pack(pady=5, ipadx=10, ipady=5)

    def select_file_from_list(self, files, title):
            def on_select(evt):
                # Evento al seleccionar un item
                w = evt.widget
                index = int(w.curselection()[0])
                value = w.get(index)
                self.selected_file = value
                top.destroy()

            top = tk.Toplevel(self)
            top.title(title)
            top.configure(bg='white')

            # Crear scrollbar
            scrollbar = tk.Scrollbar(top, orient="vertical")
            listbox = tk.Listbox(top, yscrollcommand=scrollbar.set, width=50, height=15)
            scrollbar.config(command=listbox.yview)

            # Empaquetar scrollbar y listbox
            scrollbar.pack(side="right", fill="y")
            listbox.pack(side="left", fill="both", expand=True)

            # Insertar archivos en listbox
            for file in files:
                listbox.insert(tk.END, file)

            listbox.bind('<<ListboxSelect>>', on_select)
            top.transient(self)  # set to be on top of the main window
            top.grab_set()  # ensure all input goes to our window
            self.wait_window(top)  # block until window is destroyed
            return getattr(self, 'selected_file', None)

    def generate_ecdsa_keys(self):
        if usuario:
            ECDSAGen(usuario)
            messagebox.showinfo("Éxito", "Claves ECDSA generadas y subidas a Firebase.")

    def generate_rsa_keys(self):
        usuario
        if nombre:
            RSAGen(usuario)
            messagebox.showinfo("Éxito", "Claves RSA generadas y subidas a Firebase.")

    def encrypt_sign_file(self):
        ruta_archivo_original = filedialog.askopenfilename(title="Selecciona archivo a cifrar", initialdir="imagenes")
        contratante = simpledialog.askstring("Nombre de contratante", "Ingresa el nombre del usuario que contrató el arte:")
        clave_publica_RSA = f'clave_publica_RSA_{contratante}.pem'
        local_publica_RSA = f'clavesRSA/usuarios/{clave_publica_RSA}'
        ruta_archivo_cifrado = filedialog.asksaveasfilename(title="Guardar archivo cifrado como", initialdir="archivosCifrados", defaultextension=".enc")
        clave_privada_ECDSA_ruta = filedialog.askopenfilename(title="Selecciona tu clave privada ECDSA", initialdir="clavesECDSA")
        ruta_documento = filedialog.asksaveasfilename(title="Guardar documento firmado como", initialdir="firmasDigitales", defaultextension=".sig")
        usuario
        if ruta_archivo_original and ruta_archivo_cifrado and clave_privada_ECDSA_ruta and ruta_documento and usuario:
            download_from_storage("llaves_publicas_RSA", clave_publica_RSA, local_publica_RSA)
            AESCip(ruta_archivo_original, ruta_archivo_cifrado, local_publica_RSA, contratante)
            clave_privada_ECDSA = ECDSA.cargar_clave_desde_archivo(clave_privada_ECDSA_ruta)
            firmarCifrado(clave_privada_ECDSA, ruta_archivo_cifrado, ruta_documento, contratante)
            messagebox.showinfo("Éxito", "Archivo cifrado, firmado y subido a Firebase.")

    def decrypt_verify_file(self):
        # Lista de archivos cifrados para seleccionar
            encrypted_files = list_files_in_storage("archivos_cifrados_usuarios")
            selected_encrypted_file = self.select_file_from_list(encrypted_files, "Selecciona archivo cifrado a descargar y verificar")
            local_destination = simpledialog.askstring("Nombre de archivo", "Ingresa el nombre para guardar el archivo cifrado")
            print(selected_encrypted_file)
            if selected_encrypted_file:
                file_name = selected_encrypted_file
                clave_privada_RSA = filedialog.askopenfilename(title="Selecciona tu clave privada RSA", initialdir="clavesRSA")
                nombrebajada = simpledialog.askstring("Nombre de archivo", "Ingresa el nombre para guardar el archivo descifrado")
                     
                if file_name and local_destination and clave_privada_RSA and nombrebajada:
                    AESDec(file_name, local_destination, clave_privada_RSA, nombrebajada)
                    messagebox.showinfo("Éxito", "Archivo descifrado.")

                    ## Descargar contrato
                    contrato = list_files_in_storage("archivos_firmados_usuarios")
                    selected_contract = self.select_file_from_list(contrato, "Selecciona un contrato")
                    ruta = selected_contract
                    ruta_contrato_local = filedialog.asksaveasfilename(title="Guardar contrato como", initialdir="firmasDigitales", defaultextension=".pdf")
                    download_from_storage("archivos_firmados_usuarios", ruta, ruta_contrato_local)

                    # Lista de firmas digitales para seleccionar
                    digital_signatures = list_files_in_storage("archivos_firmados_usuarios")
                    selected_signature = self.select_file_from_list(digital_signatures, "Selecciona una Firma Digital")

                    ##Verificar firma
                    ruta_archivo = filedialog.askopenfilename(title="Selecciona el contrato a verificar firma", initialdir="firmasDigitales")
                    ruta = selected_signature
                    clave_publica_ingreso = simpledialog.askstring("Clave pública del usuario", "Ingresa el nombre del usuario para verificar su firma digital:")
                    ruta_firma_local = filedialog.asksaveasfilename(title="Guardar firma como", initialdir="firmasDigitales", defaultextension=".sig")
                    download_from_storage("archivos_firmados_usuarios", ruta, ruta_firma_local)
                    ruta_descargada = ruta_firma_local
                    print(f'El archivo es: {ruta_archivo}')
                    print(f'La firma es: {ruta}')
                    print(f'La clave pública es: {clave_publica_ingreso}')
                    resultado_verificacion = verificarFirma(ruta_archivo, ruta_descargada, clave_publica_ingreso)
                    if resultado_verificacion:
                        resultado_verificacion = "Válida"
                    else:
                        resultado_verificacion = "Inválida"
                    messagebox.showinfo("Resultado de la verificación", f'Verificación: {resultado_verificacion}')
                    




# Ejecutar la aplicación
if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
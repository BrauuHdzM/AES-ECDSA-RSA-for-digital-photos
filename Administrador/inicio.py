import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import subprocess

# Inicializar Firebase
cred = credentials.Certificate("proyectocriptografia-724c1-firebase-adminsdk-bo6u7-6ab1f565fc.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# Estilos Material Design
style = ttk.Style()
style.theme_use('clam')  # Usa un tema base para personalizar

# Colores y estilos para botones y etiquetas
style.configure('TButton', background='#2196F3', foreground='white', font=('Helvetica', 12))
style.configure('TLabel', font=('Helvetica', 12), background='white')
style.configure('TEntry', font=('Helvetica', 10))

# Configuración de la ventana principal
root = tk.Tk()
root.title("Retratos Digitales - Gestión de Usuarios")
root.geometry("700x250")  # Ancho x Alto
root.configure(bg='white')  # Fondo blanco para toda la ventana

# Título y bienvenida
titulo = ttk.Label(root, text="Retratos Digitales", font=('Helvetica', 20, 'bold'), background='white')
titulo.pack(pady=(20, 5))  # Espaciado vertical
bienvenida = ttk.Label(root, text="Bienvenid@ al menú de gestión de usuarios", background='white')
bienvenida.pack(pady=(0, 20))  # Espaciado vertical

def registrar_usuario():
    registro_ventana = tk.Toplevel(root)
    registro_ventana.title("Registrar Usuario")
    registro_ventana.configure(bg='white')
    registro_ventana.geometry("400x300")

    ttk.Label(registro_ventana, text="Nombre:", background='white').pack(pady=5)
    nombre_entry = ttk.Entry(registro_ventana)
    nombre_entry.pack(pady=5)

    ttk.Label(registro_ventana, text="Nombre de usuario:", background='white').pack(pady=5)
    usuario_entry = ttk.Entry(registro_ventana)
    usuario_entry.pack(pady=5)

    ttk.Label(registro_ventana, text="Contraseña:", background='white').pack(pady=5)
    contraseña_entry = ttk.Entry(registro_ventana, show="*")
    contraseña_entry.pack(pady=5)

    def verificar_y_guardar_usuario():
        nombre = nombre_entry.get()
        usuario = usuario_entry.get()
        contraseña = contraseña_entry.get()
        tipo = "usuario"
        # Verificar si el usuario ya existe
        usuarios_ref = db.collection('usuarios')
        query = usuarios_ref.where('usuario', '==', usuario).get()

        if query:
            messagebox.showerror("Error", "El nombre de usuario ya está en uso. Por favor, elige otro.")
        else:
            # Guardar en Firestore si el usuario no existe
            usuarios_ref.add({'nombre': nombre, 'usuario': usuario, 'contrasena': contraseña, 'tipo': tipo})
            messagebox.showinfo("Éxito", "Usuario registrado exitosamente.")
            registro_ventana.destroy()

    ttk.Button(registro_ventana, text="Registrar Usuario", command=verificar_y_guardar_usuario, style='TButton').pack(pady=10, ipadx=10, ipady=5)

def iniciar_sesion():
    inicio_ventana = tk.Toplevel(root)
    inicio_ventana.title("Iniciar Sesión")
    inicio_ventana.configure(bg='white')
    inicio_ventana.geometry("400x300")

    ttk.Label(inicio_ventana, text="Nombre de usuario:", background='white').pack(pady=5)
    usuario_entry = ttk.Entry(inicio_ventana)
    usuario_entry.pack(pady=5)

    ttk.Label(inicio_ventana, text="Contraseña:", background='white').pack(pady=5)
    contraseña_entry = ttk.Entry(inicio_ventana, show="*")
    contraseña_entry.pack(pady=5)

    def verificar_usuario():
        usuario = usuario_entry.get()
        contraseña = contraseña_entry.get()

        # Verificar credenciales del usuario
        usuarios_ref = db.collection('usuarios')
        query = usuarios_ref.where('usuario', '==', usuario).where('contrasena', '==', contraseña).get()

        if query:
            for doc in query:
                tipo_usuario = doc.to_dict().get('tipo', '')
                nombre = doc.to_dict().get('nombre', '')
                if tipo_usuario == 'usuario':
                    subprocess.Popen(["python", "usuarios.py", nombre, usuario])
                elif tipo_usuario == 'administrador':
                    subprocess.Popen(["python", "administrador.py", nombre, usuario])
                
                root.destroy()  # Cierra la ventana principal
                break
        else:
            messagebox.showerror("Error", "Nombre de usuario o contraseña incorrectos.")

        inicio_ventana.destroy()

    ttk.Button(inicio_ventana, text="Iniciar Sesión", command=verificar_usuario, style='TButton').pack(pady=10, ipadx=10, ipady=5)

# Botones usando el estilo Material Design
ttk.Button(root, text="Registrar Usuario", command=registrar_usuario, style='TButton').pack(pady=10, ipadx=10, ipady=5)
ttk.Button(root, text="Iniciar Sesión", command=iniciar_sesion, style='TButton').pack(pady=10, ipadx=10, ipady=5)

root.mainloop()

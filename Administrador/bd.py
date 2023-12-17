import firebase_admin
import ECDSA
from firebase_admin import credentials
from firebase_admin import firestore
from google.cloud import storage

cred = credentials.Certificate("proyectocriptografia-724c1-firebase-adminsdk-bo6u7-6ab1f565fc.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# Consultar todos los documentos en la colección 'usuarios'
usuarios_ref = db.collection('usuarios')
docs = usuarios_ref.stream()

# Imprimir los documentos
for doc in docs:
    print(f'{doc.id} => {doc.to_dict()}')

# Suponiendo que tienes las variables 'usuario' y 'contraseña'
usuario = "nombreDeUsuario"
contraseña = "contraseñaSegura"
tipo = "usuario"
nombre = "nombre"
# Añadir un nuevo documento
usuarios_ref.add({'usuario': usuario, 'contraseña': contraseña}, {'tipo': tipo}, {'nombre': nombre})


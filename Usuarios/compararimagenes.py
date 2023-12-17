from PIL import Image
from deepdiff import DeepDiff

def comparar_metadatos(imagen1, imagen2):
    # Abrir las imágenes
    with Image.open(imagen1) as img1, Image.open(imagen2) as img2:
        # Obtener los metadatos (información EXIF) de las imágenes
        metadatos_img1 = img1.info
        metadatos_img2 = img2.info

        # Comparar los metadatos
        diferencia = DeepDiff(metadatos_img1, metadatos_img2, ignore_order=True)

        return diferencia

# Rutas de las imágenes
ruta_imagen1 = 'perro.jpg'
ruta_imagen2 = 'perro.jpg'

# Comparar y mostrar las diferencias
diferencias = comparar_metadatos(ruta_imagen1, ruta_imagen2)
print("Diferencias en los metadatos:", diferencias)

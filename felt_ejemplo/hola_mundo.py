# Paso uno:Importamos flet
import flet as ft

# Paso dos: Establecer clase de mi aplicación
class App:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Hola Mundo"
        # Aplicar interfaz 
        self.build()
        
    def build(self):
        self.page.add(
            ft.Text("¡Hola, Mundo!")
        )

# Paso tres: Ejecutar la aplicacion
if __name__ == "__main__":
    ft.app(target=App)
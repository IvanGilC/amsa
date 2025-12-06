# AMSA - Practica 3
## Grupo:
- Marco Beruet Morelli
- Ivan Gil Cañizares

---

## Desplegamiento de la infraestructura
Nuestra practica utiliza un fichero CloudFormation que crea primero la instancia Server, la configura automaticamente con un fichero bash y después genera un numero determinado de instancias Cliente.

Para hacer el desplegamiento solo hay que subir el archivo amsa_p3_template.yaml a AWS y poner la contraseña que quieres que tenga el OpenLDAP, seleccionar el numero de instancias Cliente que tienes, y seleccionar la VPC y la subred que quieres utilizar (pueden ser default).

<img width="1346" height="704" alt="creacion" src="https://github.com/user-attachments/assets/8639670e-fddc-4f9f-a6ae-c80346324fda" />

*Las instancias Cliente no se crearan hasta después de la configuracion completa del Server para asegurar que el achivo cacert.pem se copie correctamente a los clientes*

---

## Demostración de funcionamiento
### LAM
<img width="1904" height="475" alt="lam" src="https://github.com/user-attachments/assets/7b263b72-64e2-4e05-bf04-0b88da600e23" />

### Usuario (profesor)
<img width="743" height="296" alt="cliente2" src="https://github.com/user-attachments/assets/4922cf41-643c-4ddc-ab51-a5de255826db" />

### Usuario (alumno)
<img width="754" height="307" alt="cleinte1" src="https://github.com/user-attachments/assets/71eb226e-16a4-4ba2-88b4-452119519a8f" />

*Las instancias usadas para hacer las pruebas han sido mantenidas en el Workspace de AWS del Alumono Ivan Gil Cañizares (igc15@alumnes.udl.cat)*

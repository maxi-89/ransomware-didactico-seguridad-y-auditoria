# Entorno virtual

## Crear entorno virtual llamado ransom
python3 -m venv ransom

## Activar entorno virtual
### 🐧 macOS / Linux:
source ransom/bin/activate

## 🪟 Windows (PowerShell o CMD):
### ransom\Scripts\activate

## Instalar dependencias desde requirements.txt
pip install -r requirements.txt

## Verificar instalación
pip list

## (Opcional) Desactivar el entorno virtual al terminar
deactivate

🧠 Ransom Simulator (Didáctico)

ransom_simulator.py es un simulador educativo que cifra copias de archivos desde una carpeta de origen (--src) hacia una carpeta de almacenamiento (“bóveda”, --vault).
Permite también restaurar los archivos, listar el contenido cifrado y generar una nota educativa tipo "ransom note".

⚠️ Este script NO modifica los archivos originales. Está diseñado solo para uso didáctico y pruebas seguras.

🚀 Características

Cifra copias de archivos sin alterar los originales.

Permite descifrar y recuperar los archivos cifrados.

Incluye un comando para listar los archivos en la bóveda.

Genera una nota educativa (ransom_note.txt) dentro de la bóveda.

Compatible con carpetas de prueba locales.

📦 Instalación

Clona o descarga este proyecto, y asegúrate de tener Python 3.8+ instalado:

git clone https://github.com/tuusuario/ransom_simulator.git
cd ransom_simulator

🧩 Estructura de ejemplo

Supongamos que trabajas en la raíz del proyecto con tres carpetas:

ransom_simulator/
├── ransom_simulator.py
├── data_src/      # Archivos originales
├── vault_encrypted/  # Carpeta donde se guardan las copias cifradas
└── data_restored/ # Carpeta de salida al descifrar

💡 Uso básico
1️⃣ Cifrar archivos (simulación del ataque)
python ransom_simulator.py encrypt --src data_src --vault vault_encrypted --passphrase-prompt


📄 Esto:

Cifra copias de los archivos dentro de vault_encrypted/

Genera un archivo ransom_note.txt en la bóveda

No modifica nada dentro de data_src/

2️⃣ Listar archivos cifrados
python ransom_simulator.py list --vault vault_encrypted


📋 Muestra el listado de archivos presentes en la bóveda cifrada.

3️⃣ Restaurar archivos (descifrar)
python ransom_simulator.py decrypt --vault vault_encrypted --out data_restored --passphrase-prompt


📂 Recupera los archivos cifrados en una nueva carpeta data_restored/.

4️⃣ Generar o personalizar una nota educativa
python ransom_simulator.py note --vault vault_encrypted --message "Tus archivos fueron cifrados con fines educativos."


📝 Crea o sobrescribe ransom_note.txt en la bóveda con el mensaje indicado.

⚠️ Recomendaciones

Usa solo carpetas de prueba.

No ejecutes este simulador sobre datos reales o sensibles.

Ideal para demos educativas, formación en ciberseguridad o laboratorios controlados.

# 🧰  Ejemplo completo


## Cifrar
python ransom_simulator.py encrypt --src data_src --vault vault_encrypted --passphrase-prompt

## Listar contenido cifrado
python ransom_simulator.py list --vault vault_encrypted

## Restaurar (descifrar)
python ransom_simulator.py decrypt --vault vault_encrypted --out data_restored --passphrase-prompt

# 🧾 Licencia

Proyecto educativo bajo licencia MIT.
No se asume ninguna responsabilidad por uso indebido del código.
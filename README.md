# SecureVault CR — Intercambio Seguro de Archivos

Sistema de intercambio seguro de archivos mediante cifrado híbrido y firma digital, desarrollado para el curso Criptografía II (CIB-06) de la Maestría en Ciberseguridad en UISIL[cite: 1, 2].

## Arquitectura Criptográfica
- **Cifrado Simétrico**: AES-256-GCM con claves de 256 bits y nonce de 96 bits generados mediante CSPRNG (`os.urandom`)[cite: 4, 6].
- **Encapsulamiento Asimétrico**: RSA-OAEP con SHA-256 para proteger la clave de sesión simétrica[cite: 4].
- **Firma Digital e Integridad**: RSA-PSS con SHA-256 cubriendo la serialización canónica de cabeceras, destinatario, nonce y texto cifrado[cite: 4].
- **Prevención de Replay Attacks**: Historial persistente en base de datos SQLite para registrar identificadores de 128 bits de paquetes aceptados[cite: 3, 5].
- **Protección de Llaves Privadas**: Formato PKCS#8 protegido localmente bajo contraseña[cite: 3].

## Estructura del Repositorio
- `crypto_core.py`: API criptográfica central con separación de responsabilidades[cite: 5].
- `app_gui.py`: Interfaz gráfica multiperfil en Tkinter[cite: 3].
- `run_tests.py`: Suite automatizada para pruebas de seguridad (P1 a P8) y experimento de aleatoriedad (20 envíos)[cite: 6].
- `requirements.txt`: Dependencias del proyecto.

## Instrucciones de Ejecución

### Requisitos
- Python 3.10+
- `pip install -r requirements.txt`
- Soporte para Tkinter (`sudo apt install python3-tk`)

### 1. Ejecución de Pruebas Automatizadas (P1 - P8 y 20 Envíos)
Ejecute en terminal:
python3 run_tests.py

### 2. Ejecución de la Interfaz Gráfica (Multi-instancia)
Para simular el intercambio entre dos partes independientes:

Terminal 1 (Alicia):
python3 app_gui.py --profile profile_alicia --user Alicia

Terminal 2 (Bruno):
python3 app_gui.py --profile profile_bruno --user Bruno

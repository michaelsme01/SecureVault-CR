import os
import json
import base64
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB límite

class CryptoCore:
    def __init__(self, profile_dir: str):
        self.profile_dir = profile_dir
        os.makedirs(self.profile_dir, exist_ok=True)
        self.db_path = os.path.join(self.profile_dir, "vault_history.db")
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tipo TEXT,
                    package_id TEXT,
                    fecha TEXT,
                    contraparte TEXT,
                    filename TEXT,
                    estado TEXT,
                    detalle TEXT
                )
            """)

    @staticmethod
    def get_fingerprint(public_bytes: bytes) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_bytes)
        return digest.finalize().hex()

    def tiene_identidad(self) -> bool:
        return os.path.exists(os.path.join(self.profile_dir, "enc_private.pem")) and \
               os.path.exists(os.path.join(self.profile_dir, "sig_private.pem"))

    def crearIdentidad(self, password: str = "clave123"):
        if not password or len(password) < 4:
            raise ValueError("La contraseña debe tener al menos 4 caracteres.")
        
        pwd_bytes = password.encode("utf-8")
        enc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sig_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        enc_pem = enc_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd_bytes)
        )
        sig_pem = sig_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd_bytes)
        )
        with open(os.path.join(self.profile_dir, "enc_private.pem"), "wb") as f:
            f.write(enc_pem)
        with open(os.path.join(self.profile_dir, "sig_private.pem"), "wb") as f:
            f.write(sig_pem)

    def _load_private_keys(self, password: str = "clave123"):
        pwd_bytes = password.encode("utf-8")
        try:
            with open(os.path.join(self.profile_dir, "enc_private.pem"), "rb") as f:
                enc_priv = serialization.load_pem_private_key(f.read(), password=pwd_bytes)
            with open(os.path.join(self.profile_dir, "sig_private.pem"), "rb") as f:
                sig_priv = serialization.load_pem_private_key(f.read(), password=pwd_bytes)
            return enc_priv, sig_priv
        except Exception:
            raise ValueError("Contraseña incorrecta o llaves privadas dañadas.")

    def exportarPublicas(self, password: str = "clave123") -> dict:
        enc_priv, sig_priv = self._load_private_keys(password)
        enc_pub = enc_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sig_pub = sig_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "enc_public_pem": enc_pub.decode("utf-8"),
            "sig_public_pem": sig_pub.decode("utf-8"),
            "enc_fingerprint": self.get_fingerprint(enc_pub),
            "sig_fingerprint": self.get_fingerprint(sig_pub)
        }

    def crearEnvio(self, filepath: str, recipient_enc_pub_pem: str, recipient_label: str = "Destinatario", password: str = "clave123") -> str:
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            raise ValueError("El archivo supera el límite de 5 MiB.")

        with open(filepath, "rb") as f:
            plaintext = f.read()

        _, sig_priv = self._load_private_keys(password)
        recipient_enc_key = serialization.load_pem_public_key(recipient_enc_pub_pem.encode("utf-8"))

        package_id = os.urandom(16).hex()
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        enc_aes_key = recipient_enc_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        my_publics = self.exportarPublicas(password)
        safe_filename = os.path.basename(filepath)
        
        payload = {
            "version": "1.0",
            "algorithm": "AES-256-GCM/RSA-OAEP/RSA-PSS",
            "package_id": package_id,
            "sender_sig_fingerprint": my_publics["sig_fingerprint"],
            "recipient_enc_fingerprint": self.get_fingerprint(recipient_enc_pub_pem.encode("utf-8")),
            "filename": safe_filename,
            "enc_key_b64": base64.b64encode(enc_aes_key).decode("ascii"),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "tag_b64": base64.b64encode(tag).decode("ascii")
        }

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = sig_priv.sign(
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        package = {
            "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii")
        }

        # Registrar el evento de envío en el historial local
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO history (tipo, package_id, fecha, contraparte, filename, estado, detalle) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("ENVÍO", package_id, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), recipient_label, safe_filename, "CIFRADO", "AES-256-GCM + RSA-OAEP / Firmado RSA-PSS")
            )

        return json.dumps(package, indent=2)

    def recibirEnvio(self, package_json_str: str, trusted_sender_sig_pub_pem: str, sender_label: str, output_dir: str, password: str = "clave123") -> str:
        if len(package_json_str) > (MAX_FILE_SIZE * 3):
            raise ValueError("El paquete recibido supera el límite máximo permitido.")

        pkg = json.loads(package_json_str)
        if "payload_b64" not in pkg or "signature_b64" not in pkg:
            raise ValueError("Formato de paquete corrupto o incompleto.")

        payload_bytes = base64.b64decode(pkg["payload_b64"])
        signature = base64.b64decode(pkg["signature_b64"])

        sender_sig_pub = serialization.load_pem_public_key(trusted_sender_sig_pub_pem.encode("utf-8"))
        try:
            sender_sig_pub.verify(
                signature,
                payload_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception:
            raise ValueError("Firma digital inválida: paquete manipulado o emisor no coincide.")

        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("version") != "1.0":
            raise ValueError("Versión de protocolo no soportada.")

        package_id = payload["package_id"]

        # Control persistente de repetición: solo verificar sobre paquetes aceptados previamente
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT package_id FROM history WHERE tipo = 'RECEPCIÓN' AND package_id = ?", (package_id,))
            if cur.fetchone():
                raise ValueError(f"Ataque de repetición detectado: el paquete {package_id} ya fue aceptado previamente.")

        enc_priv, _ = self._load_private_keys(password)
        enc_aes_key = base64.b64decode(payload["enc_key_b64"])
        try:
            aes_key = enc_priv.decrypt(
                enc_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            raise ValueError("Destinatario incorrecto: no es posible descifrar la clave con este perfil.")

        nonce = base64.b64decode(payload["nonce_b64"])
        ciphertext = base64.b64decode(payload["ciphertext_b64"])
        tag = base64.b64decode(payload["tag_b64"])

        aesgcm = AESGCM(aes_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        except Exception:
            raise ValueError("Fallo en verificación de integridad del contenido (GCM Tag inválido).")

        safe_filename = os.path.basename(payload["filename"])
        dest_path = os.path.join(output_dir, f"recuperado_{safe_filename}")
        with open(dest_path, "wb") as f:
            f.write(plaintext)

        # Registrar recepción aceptada
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO history (tipo, package_id, fecha, contraparte, filename, estado, detalle) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("RECEPCIÓN", package_id, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), sender_label, safe_filename, "ACEPTADO", "AES-256-GCM / RSA-PSS verificado")
            )

        return dest_path

    def consultarHistorial(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT tipo, package_id, fecha, contraparte, filename, estado, detalle FROM history ORDER BY id DESC")
            return cur.fetchall()

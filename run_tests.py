import os
import json
import base64
from crypto_core import CryptoCore

def run_all_tests():
    print("=== INICIANDO BATERÍA DE PRUEBAS DE SEGURIDAD (P1 - P8) ===")
    
    # 1. Preparar entornos aislados
    for d in ["profile_alicia", "profile_bruno", "profile_carla", "profile_temp"]:
        if os.path.exists(d):
            import shutil
            shutil.rmtree(d)

    alicia = CryptoCore("profile_alicia")
    bruno = CryptoCore("profile_bruno")
    carla = CryptoCore("profile_carla")
    
    alicia.crearIdentidad()
    bruno.crearIdentidad()
    carla.crearIdentidad()
    
    alicia_pub = alicia.exportarPublicas()
    bruno_pub = bruno.exportarPublicas()
    
    sample_path = "test_doc.txt"
    with open(sample_path, "wb") as f:
        f.write(b"Prueba de intercambio seguro - CIB-06 - UISIL 2026.")

    # P1: Entrega válida
    pkg_str = alicia.crearEnvio(sample_path, bruno_pub["enc_public_pem"], "Bruno")
    out = bruno.recibirEnvio(pkg_str, alicia_pub["sig_public_pem"], "Alicia", "profile_bruno")
    with open(out, "rb") as f:
        recovered = f.read()
    assert recovered == b"Prueba de intercambio seguro - CIB-06 - UISIL 2026."
    print("[+] P1 (Entrega válida): SUPERADA. Archivo íntegro recuperado.")

    # P2: Destinatario incorrecto (Carla)
    try:
        carla.recibirEnvio(pkg_str, alicia_pub["sig_public_pem"], "Alicia", "profile_carla")
        print("[-] P2 FALLÓ: Carla no debió poder abrir el archivo.")
    except Exception as e:
        print(f"[+] P2 (Destinatario incorrecto): SUPERADA. Rechazado ({e}).")

    # P3: Contenido alterado
    pkg_dict = json.loads(pkg_str)
    payload_raw = base64.b64decode(pkg_dict["payload_b64"])
    payload = json.loads(payload_raw.decode("utf-8"))
    raw_ct = base64.b64decode(payload["ciphertext_b64"])
    corrupted_ct = bytes([raw_ct[0] ^ 0xFF]) + raw_ct[1:]
    payload["ciphertext_b64"] = base64.b64encode(corrupted_ct).decode("ascii")
    tampered_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    pkg_dict["payload_b64"] = base64.b64encode(tampered_bytes).decode("ascii")
    try:
        bruno.recibirEnvio(json.dumps(pkg_dict), alicia_pub["sig_public_pem"], "Alicia", "profile_bruno")
        print("[-] P3 FALLÓ: Se aceptó contenido alterado.")
    except Exception as e:
        print(f"[+] P3 (Contenido alterado): SUPERADA. Detectado por firma ({e}).")

    # P4: Cabecera alterada
    pkg_dict = json.loads(pkg_str)
    payload_raw = base64.b64decode(pkg_dict["payload_b64"])
    payload = json.loads(payload_raw.decode("utf-8"))
    payload["package_id"] = "00000000000000000000000000000000"
    tampered_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    pkg_dict["payload_b64"] = base64.b64encode(tampered_bytes).decode("ascii")
    try:
        bruno.recibirEnvio(json.dumps(pkg_dict), alicia_pub["sig_public_pem"], "Alicia", "profile_bruno")
        print("[-] P4 FALLÓ: Cabecera alterada fue aceptada.")
    except Exception as e:
        print(f"[+] P4 (Cabecera alterada): SUPERADA. Rechazo por firma ({e}).")

    # P5: Clave sustituida
    try:
        bruno.recibirEnvio(pkg_str, bruno_pub["sig_public_pem"], "Atacante", "profile_bruno")
        print("[-] P5 FALLÓ: Se aceptó clave no confiable.")
    except Exception as e:
        print(f"[+] P5 (Clave sustituida): SUPERADA. Rechazado ({e}).")

    # P6: Ataque de repetición
    try:
        bruno.recibirEnvio(pkg_str, alicia_pub["sig_public_pem"], "Alicia", "profile_bruno")
        print("[-] P6 FALLÓ: Se aceptó paquete duplicado.")
    except Exception as e:
        print(f"[+] P6 (Repetición / Replay): SUPERADA. Detectado en base de datos ({e}).")

    # P7: Formato y tamaño
    try:
        fake_huge = "huge.bin"
        with open(fake_huge, "wb") as f:
            f.seek((5 * 1024 * 1024) + 10)
            f.write(b"\0")
        alicia.crearEnvio(fake_huge, bruno_pub["enc_public_pem"], "Bruno")
        print("[-] P7 FALLÓ: Archivo mayor a 5MB aceptado.")
    except ValueError as e:
        print(f"[+] P7 (Formato y tamaño): SUPERADA. Rechazo controlado ({e}).")
    finally:
        if os.path.exists("huge.bin"): os.remove("huge.bin")

    # P8: Cifrado autenticado directo
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k = AESGCM.generate_key(bit_length=256)
    n = os.urandom(12)
    aes = AESGCM(k)
    ct = aes.encrypt(n, b"test", None)
    try:
        aes.decrypt(n, ct[:-1] + b"\x00", None)
        print("[-] P8 FALLÓ: Tag GCM corrupto aceptado.")
    except Exception:
        print("[+] P8 (Cifrado autenticado directo): SUPERADA. AES-GCM detecta manipulación.")

    # Experimento de 20 envíos
    print("\n=== EXPERIMENTO DE 20 ENVÍOS (EVALUACIÓN CSPRNG) ===")
    ids, nonces, pkgs = set(), set(), set()
    b_temp = CryptoCore("profile_temp")
    b_temp.crearIdentidad()
    b_temp_pub = b_temp.exportarPublicas()

    for i in range(1, 21):
        p = alicia.crearEnvio(sample_path, b_temp_pub["enc_public_pem"], "TempUser")
        pkgs.add(p)
        
        # Decodificar Base64 canónico
        pkg_obj = json.loads(p)
        payload_bytes = base64.b64decode(pkg_obj["payload_b64"])
        parsed = json.loads(payload_bytes.decode("utf-8"))
        
        ids.add(parsed["package_id"])
        nonces.add(parsed["nonce_b64"])
        
        # Probar recepción y recuperación íntegra
        rec_path = b_temp.recibirEnvio(p, alicia_pub["sig_public_pem"], "Alicia", "profile_temp")
        if os.path.exists(rec_path):
            os.remove(rec_path)

    print(f"Total paquetes generados: 20")
    print(f"Total paquetes únicos:     {len(pkgs)} / 20")
    print(f"Total package_ids únicos:  {len(ids)} / 20")
    print(f"Total nonces únicos:       {len(nonces)} / 20")
    print("[+] Todos los 20 envíos fueron recuperados exitosamente.")

if __name__ == "__main__":
    run_all_tests()

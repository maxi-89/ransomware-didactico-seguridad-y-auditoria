#!/usr/bin/env python3
from pathlib import Path
import argparse
import os
import sys
import json
import base64
from getpass import getpass
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time

# --- Configurables ---
KDF_ITER = 250_000
SALT_LEN = 16
NONCE_LEN = 12
MASTER_KEY_LEN = 32  # AES-256
ENC_EXT = ".enc"
METADATA_FILENAME = "metadata.json"
NOTE_FILENAME = "ransom_note.txt"

# --- Helpers: KDF / AES-GCM ---
def derive_key(passphrase: bytes, salt: bytes, iterations: int = KDF_ITER) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase)

def encrypt_bytes_aesgcm(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce + ct

def decrypt_bytes_aesgcm(key: bytes, blob: bytes, aad: bytes = None) -> bytes:
    aes = AESGCM(key)
    nonce = blob[:NONCE_LEN]
    ct = blob[NONCE_LEN:]
    return aes.decrypt(nonce, ct, aad)

# --- Filename encoding helpers ---
def encode_name(rel_path: str) -> str:
    b = rel_path.encode('utf-8')
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

def decode_name(encoded: str) -> str:
    pad = '=' * (-len(encoded) % 4)
    return base64.urlsafe_b64decode((encoded + pad).encode('ascii')).decode('utf-8')

# --- File operations ---
def scan_src(src_dir: Path):
    files = []
    for root, dirs, filenames in os.walk(src_dir):
        for fn in filenames:
            full = Path(root) / fn
            # Skip if inside vault by accident
            if '.git' in full.parts:
                continue
            files.append(full)
    return files

def build_metadata(vault_dir: Path, wrapped_master_b64: str, salt_b64: str, files_meta: dict):
    meta = {
        'wrapped_master_b64': wrapped_master_b64,
        'salt_b64': salt_b64,
        'kdf': 'PBKDF2HMAC-SHA256',
        'kdf_iter': KDF_ITER,
        'files': files_meta
    }
    (vault_dir / METADATA_FILENAME).write_text(json.dumps(meta, indent=2, ensure_ascii=False))

def load_metadata(vault_dir: Path):
    p = vault_dir / METADATA_FILENAME
    if not p.exists():
        raise FileNotFoundError("metadata.json no encontrado en vault")
    return json.loads(p.read_text())

# --- CLI actions ---
def cmd_encrypt(src: Path, vault: Path, passphrase: bytes):
    if not src.exists() or not src.is_dir():
        print("ERROR: --src debe ser un directorio válido.")
        sys.exit(1)
    vault.mkdir(parents=True, exist_ok=True)

    # Master key (random)
    master_key = secrets.token_bytes(MASTER_KEY_LEN)
    salt = secrets.token_bytes(SALT_LEN)
    kek = derive_key(passphrase, salt)
    wrapped_master = encrypt_bytes_aesgcm(kek, master_key)
    wrapped_b64 = base64.b64encode(wrapped_master).decode('ascii')
    salt_b64 = base64.b64encode(salt).decode('ascii')

    files = scan_src(src)
    files_meta = {}

    print(f"Encontrados {len(files)} archivos en {src}. Cifrando COPIAS en {vault} ...")
    for f in files:
        rel = f.relative_to(src).as_posix()
        with f.open('rb') as fh:
            data = fh.read()
        enc_blob = encrypt_bytes_aesgcm(master_key, data)
        encoded_name = encode_name(rel) + ENC_EXT
        out_path = vault / encoded_name
        out_path.write_bytes(enc_blob)
        files_meta[encoded_name] = {
            'original_path': rel,
            'size': len(data)
        }
        print(f"  -> {rel}  -> {encoded_name}")

    build_metadata(vault, wrapped_b64, salt_b64, files_meta)

    # Create an educational ransom note
    note_text = (
        "NOTA (educativa):\n\n"
        "Este vault contiene COPIAS CIFRADAS de archivos en un entorno de PRUEBA.\n"
        "NO se han modificado los archivos originales.\n\n"
        "Para restaurar los archivos desde este vault, use la herramienta proporcionada\n"
        "y la passphrase que se utilizó al cifrar.\n\n"
        "Este ejercicio demuestra cifrado simétrico (AES-GCM), derivación de claves (PBKDF2),\n"
        "y la importancia de backups y procedimientos de recuperación.\n\n"
        "FIN DE LA NOTA.\n"
    )
    (vault / NOTE_FILENAME).write_text(note_text)
    print("\nCifrado completado. metadata.json y ransom_note.txt creados en el vault.")
    print("IMPORTANTE: Esto cifra COPIAS. Los archivos originales NO se tocan.")

def cmd_decrypt(vault: Path, out_dir: Path, passphrase: bytes):
    if not vault.exists() or not (vault / METADATA_FILENAME).exists():
        print("ERROR: vault inválido o falta metadata.json")
        sys.exit(1)
    meta = load_metadata(vault)
    salt = base64.b64decode(meta['salt_b64'])
    wrapped_master = base64.b64decode(meta['wrapped_master_b64'])
    kek = derive_key(passphrase, salt)
    try:
        master_key = decrypt_bytes_aesgcm(kek, wrapped_master)
    except Exception as e:
        print("ERROR: passphrase incorrecta o metadata corrupta.")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    files_meta = meta.get('files', {})
    print(f"Restaurando {len(files_meta)} archivos en {out_dir} ...")
    for enc_name, info in files_meta.items():
        enc_path = vault / enc_name
        if not enc_path.exists():
            print(f"  SKIP: {enc_name} faltante en vault")
            continue
        try:
            blob = enc_path.read_bytes()
            plaintext = decrypt_bytes_aesgcm(master_key, blob)
            original_rel = info['original_path']
            dest_path = out_dir / original_rel
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(plaintext)
            print(f"  Restaurado: {original_rel}")
        except Exception as e:
            print(f"  ERROR al restaurar {enc_name}: {e}")
    print("Restauración completada. Verifica los archivos en", out_dir)

def cmd_list(vault: Path):
    if not vault.exists() or not (vault / METADATA_FILENAME).exists():
        print("ERROR: vault inválido o falta metadata.json")
        sys.exit(1)
    meta = load_metadata(vault)
    files = meta.get('files', {})
    print(f"Vault: {vault}")
    print(f"Archivos cifrados: {len(files)}")
    for enc_name, info in files.items():
        try:
            orig = info.get('original_path', '<desconocido>')
            size = info.get('size', '?')
            print(f"  {enc_name}  -> {orig}  ({size} bytes)")
        except Exception:
            print(f"  {enc_name}")

def cmd_note(vault: Path, message: str = None):
    vault.mkdir(parents=True, exist_ok=True)
    if message is None:
        message = (
            "NOTA (educativa): Este vault contiene COPIAS CIFRADAS (ejercicio didáctico).\n"
            "Use la herramienta de restauración con la passphrase correcta.\n"
        )
    (vault / NOTE_FILENAME).write_text(message)
    print("Nota escrita en vault:", vault / NOTE_FILENAME)

# --- Argparse ---
def build_parser():
    p = argparse.ArgumentParser(description="Simulador seguro de 'ransomware' (cifra COPIAS).")
    sub = p.add_subparsers(dest='cmd', required=True)

    enc = sub.add_parser('encrypt', help='Cifrar copias desde --src a --vault')
    enc.add_argument('--src', required=True, type=Path, help='Directorio fuente (pruebas) a escanear')
    enc.add_argument('--vault', required=True, type=Path, help='Directorio donde guardar archivos cifrados y metadata')
    enc.add_argument('--passphrase-prompt', action='store_true', help='Pedir passphrase (recomendado)')

    dec = sub.add_parser('decrypt', help='Descifrar desde vault a --out (restaurar copias)')
    dec.add_argument('--vault', required=True, type=Path, help='Directorio vault')
    dec.add_argument('--out', required=True, type=Path, help='Directorio donde restaurar archivos (copias)')
    dec.add_argument('--passphrase-prompt', action='store_true', help='Pedir passphrase')

    lst = sub.add_parser('list', help='Listar contenido del vault')
    lst.add_argument('--vault', required=True, type=Path, help='Directorio vault')

    note = sub.add_parser('note', help='Crear/actualizar nota educativa dentro del vault')
    note.add_argument('--vault', required=True, type=Path, help='Directorio vault')
    note.add_argument('--message', required=False, help='Mensaje de la nota (opcional)')

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == 'encrypt':
        if args.passphrase_prompt:
            passphrase = getpass("Passphrase para proteger la clave maestra: ").encode()
            passphrase2 = getpass("Confirmar passphrase: ").encode()
            if not constant_time.bytes_eq(passphrase, passphrase2):
                print("ERROR: passphrases no coinciden.")
                sys.exit(1)
        else:
            print("AVISO: Se recomienda usar --passphrase-prompt. No se permite passphrase por CLI por seguridad.")
            print("Se aborta por seguridad.")
            sys.exit(1)
        cmd_encrypt(args.src, args.vault, passphrase)

    elif args.cmd == 'decrypt':
        if args.passphrase_prompt:
            passphrase = getpass("Passphrase para desbloquear la clave maestra: ").encode()
        else:
            print("AVISO: Se recomienda usar --passphrase-prompt. No se permite passphrase por CLI por seguridad.")
            print("Se aborta por seguridad.")
            sys.exit(1)
        cmd_decrypt(args.vault, args.out, passphrase)

    elif args.cmd == 'list':
        cmd_list(args.vault)

    elif args.cmd == 'note':
        cmd_note(args.vault, args.message)

if __name__ == '__main__':
    main()

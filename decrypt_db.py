# decrypt_db.py
# -*- coding: utf-8 -*-
"""
Утилита для расшифровки passwords.enc → passwords.db
Спросит мастер-пароль (до 3 попыток), затем расшифрует.
Запускается из папки проекта:
    python decrypt_db.py
"""

import os, sys, json, base64
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CONFIG_FILE  = 'config.json'
ENCRYPTED_DB = 'passwords.enc'
PLAIN_DB     = 'passwords.db'
ITERATIONS   = 200_000
MAX_TRIES    = 3

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        salt   = base64.b64decode(cfg['salt'])
        stored = base64.b64decode(cfg['hash'])
        return salt, stored
    except Exception as e:
        print('❌ Не удалось прочитать config.json:', e)
        sys.exit(1)

def ask_master_password(salt, stored):
    for attempt in range(1, MAX_TRIES+1):
        pw = getpass(f'Введите мастер-пароль (попытка {attempt}/{MAX_TRIES}): ')
        key = derive_key(pw, salt)
        if key == stored:
            return key
        print('❌ Неверный пароль.')
    print('🚫 Превышено число попыток, выходим.')
    sys.exit(1)

def main():
    salt, stored = load_config()
    key = ask_master_password(salt, stored)

    if not os.path.exists(ENCRYPTED_DB):
        print(f'❌ Файл {ENCRYPTED_DB} не найден.')
        sys.exit(1)

    data = open(ENCRYPTED_DB, 'rb').read()
    fernet = Fernet(key)
    try:
        plain = fernet.decrypt(data)
    except InvalidToken:
        print('❌ Ошибка при расшифровке: возможно, файл повреждён.')
        sys.exit(1)

    with open(PLAIN_DB, 'wb') as f:
        f.write(plain)
    print(f'✅ {PLAIN_DB} готов, открывайте его в DB Browser.')
    sys.exit(0)

if __name__ == '__main__':
    main()

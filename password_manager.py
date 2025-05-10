# -*- coding: utf-8 -*-
"""
Менеджер паролей v3
Русский интерфейс, логистическая генерация паролей,
вход по мастер-паролю с хранением хеша в config.json.
Требования:
    pip install PySide6 SQLAlchemy cryptography
"""

import sys
import os
import time
import json
import base64
import hmac
import hashlib

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QPushButton, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QLabel, QDialog, QMessageBox, QInputDialog
)
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Константы и пути ---
CONFIG     = 'config.json'
DB_FILE    = 'passwords.db'
ITERATIONS = 200_000


# --- Работа с конфигом (мастер-пароль) ---
def hash_password(password: str, salt: bytes) -> bytes:
    """Выдает 32-байтовый хеш пароля по PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def init_config():
    """Если нет config.json — спрашиваем новый мастер-пароль и сохраняем хеш+соль."""
    if not os.path.exists(CONFIG):
        pw, ok = QInputDialog.getText(
            None, 'Установка пароля',
            'Придумайте мастер-пароль:',
            QLineEdit.Password
        )
        if not ok or not pw:
            sys.exit()
        salt     = os.urandom(16)
        pwd_hash = hash_password(pw, salt)
        with open(CONFIG, 'w', encoding='utf-8') as f:
            json.dump({
                'salt': base64.b64encode(salt).decode(),
                'hash': base64.b64encode(pwd_hash).decode()
            }, f, indent=2)

def check_master_password():
    """Проверяем введенный пароль по хешу из config.json."""
    try:
        with open(CONFIG, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        QMessageBox.critical(None, 'Ошибка', 'Не удалось прочитать config.json.')
        sys.exit()
    salt   = base64.b64decode(cfg.get('salt',''))
    stored = base64.b64decode(cfg.get('hash',''))

    pw, ok = QInputDialog.getText(
        None, 'Авторизация',
        'Введите мастер-пароль:',
        QLineEdit.Password
    )
    if not ok:
        sys.exit()
    candidate = hash_password(pw, salt)
    if not hmac.compare_digest(candidate, stored):
        QMessageBox.critical(None, 'Ошибка', 'Неверный пароль.')
        sys.exit()


# --- Модель базы данных ---
Base = declarative_base()
class Entry(Base):
    __tablename__ = 'entries'
    id       = Column(Integer, primary_key=True)
    service  = Column(String,  nullable=False)
    login    = Column(String)
    password = Column(String,  nullable=False)
    note     = Column(String)


# --- Логика менеджера паролей ---
class PasswordManager:
    def __init__(self):
        db_path = os.path.join(os.path.dirname(__file__), DB_FILE)
        self.engine  = create_engine(f'sqlite:///{db_path}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_entry(self, service, login, password, note):
        session = self.Session()
        entry   = Entry(service=service, login=login,
                        password=password, note=note)
        session.add(entry)
        session.commit()
        session.close()

    def get_entries(self):
        session = self.Session()
        items   = session.query(Entry).all()
        session.close()
        return items


# --- Диалог добавления новой записи ---
class AddDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Новая запись')

        self.service_input  = QLineEdit()
        self.login_input    = QLineEdit()
        self.password_input = QLineEdit()
        self.note_input     = QLineEdit()

        gen_btn  = QPushButton('Сгенерировать пароль')
        gen_btn.clicked.connect(self.generate_password)
        save_btn = QPushButton('Сохранить')
        save_btn.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(QLabel('Сервис:'))
        layout.addWidget(self.service_input)
        layout.addWidget(QLabel('Логин:'))
        layout.addWidget(self.login_input)
        layout.addWidget(QLabel('Пароль:'))
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password_input)
        pw_row.addWidget(gen_btn)
        layout.addLayout(pw_row)
        layout.addWidget(QLabel('Примечание:'))
        layout.addWidget(self.note_input)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def generate_password(self):
        length, ok = QInputDialog.getInt(
            self, 'Длина пароля',
            'Укажите длину пароля:', 16, 6, 64
        )
        if not ok:
            return
        # Генерация по логистической карте: x_{n+1}=r·x_n·(1−x_n)
        import string
        r     = 3.99
        x     = time.time() % 1
        chars = string.ascii_letters + string.digits + string.punctuation
        pwd   = ''
        for _ in range(length):
            x   = r * x * (1 - x)
            idx = int(abs(x) * len(chars)) % len(chars)
            pwd += chars[idx]
        self.password_input.setText(pwd)


# --- Главное окно приложения ---
class MainWindow(QMainWindow):
    def __init__(self, manager: PasswordManager):
        super().__init__()
        self.manager = manager
        self.setWindowTitle('Менеджер паролей v3')

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ['ID', 'Сервис', 'Логин', 'Пароль', 'Примечание']
        )
        self.load_entries()

        add_btn = QPushButton('Добавить запись')
        add_btn.clicked.connect(self.add_entry)

        container = QWidget()
        vlay      = QVBoxLayout()
        vlay.addWidget(self.table)
        vlay.addWidget(add_btn)
        container.setLayout(vlay)
        self.setCentralWidget(container)

    def load_entries(self):
        rows = self.manager.get_entries()
        self.table.setRowCount(len(rows))
        for i, e in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(str(e.id)))
            self.table.setItem(i, 1, QTableWidgetItem(e.service))
            self.table.setItem(i, 2, QTableWidgetItem(e.login or ''))
            self.table.setItem(i, 3, QTableWidgetItem(e.password))
            self.table.setItem(i, 4, QTableWidgetItem(e.note or ''))

    def add_entry(self):
        dlg = AddDialog()
        if dlg.exec():
            svc  = dlg.service_input.text().strip()
            pwd  = dlg.password_input.text().strip()
            if not svc or not pwd:
                QMessageBox.warning(self, 'Ошибка',
                                    'Поля "Сервис" и "Пароль" обязательны')
                return
            lg   = dlg.login_input.text().strip()
            note = dlg.note_input.text().strip()
            self.manager.add_entry(svc, lg, pwd, note)
            self.load_entries()


# --- Точка входа ---
def main():
    app = QApplication(sys.argv)

    # 1) Инициализируем и проверяем мастер-пароль
    init_config()
    check_master_password()

    # 2) Основное окно
    manager = PasswordManager()
    win     = MainWindow(manager)
    win.resize(800, 450)
    win.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()

# -*- coding: utf-8 -*-
"""
Менеджер паролей v4
1) Русский интерфейс
2) Мастер-пароль (можно менять)
3) Шифрование всей базы через Fernet
4) Добавление и удаление записей
Требования:
    pip install PySide6 SQLAlchemy cryptography
"""

import sys, os, json, base64, hmac, time, string
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QPushButton, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QLabel, QDialog, QMessageBox, QInputDialog, QMenuBar
)
# ACTION надо импортировать из QtGui, а не из QtWidgets
from PySide6.QtGui     import QAction

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# --- Константы и пути ---
CONFIG_FILE    = 'config.json'
ENCRYPTED_DB   = 'passwords.enc'
PLAIN_DB       = 'passwords.db'
ITERATIONS     = 200_000

# --- Mастер-пароль + Fernet-ключ ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def init_config():
    if not os.path.exists(CONFIG_FILE):
        pw, ok = QInputDialog.getText(
            None, 'Установка мастер-пароля',
            'Придумайте мастер-пароль:', QLineEdit.Password
        )
        if not ok or not pw:
            sys.exit()
        salt = os.urandom(16)
        key  = derive_key(pw, salt)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                'salt': base64.b64encode(salt).decode(),
                'hash': base64.b64encode(key).decode()
            }, f, indent=2)

def check_master_password() -> bytes:
    try:
        cfg    = json.load(open(CONFIG_FILE,'r',encoding='utf-8'))
        salt   = base64.b64decode(cfg['salt'])
        stored = base64.b64decode(cfg['hash'])
    except Exception:
        QMessageBox.critical(None, 'Ошибка', 'Не удалось прочитать config.json.')
        sys.exit()

    pw, ok = QInputDialog.getText(
        None, 'Авторизация',
        'Введите мастер-пароль:', QLineEdit.Password
    )
    if not ok:
        sys.exit()
    key = derive_key(pw, salt)
    if not hmac.compare_digest(key, stored):
        QMessageBox.critical(None, 'Ошибка', 'Неверный мастер-пароль.')
        sys.exit()
    return key

def change_master_password(old_key: bytes):
    new_pw, ok = QInputDialog.getText(
        None, 'Смена мастер-пароля',
        'Введите новый мастер-пароль:', QLineEdit.Password
    )
    if not ok or not new_pw:
        return
    new_salt = os.urandom(16)
    new_key  = derive_key(new_pw, new_salt)

    # перешифровываем базу
    f_old = Fernet(old_key)
    data  = f_old.decrypt(open(ENCRYPTED_DB,'rb').read())
    f_new = Fernet(new_key)
    open(ENCRYPTED_DB,'wb').write(f_new.encrypt(data))

    # обновляем config.json
    with open(CONFIG_FILE,'w',encoding='utf-8') as f:
        json.dump({
            'salt': base64.b64encode(new_salt).decode(),
            'hash': base64.b64encode(new_key).decode()
        }, f, indent=2)
    QMessageBox.information(None, 'Успех', 'Мастер-пароль изменён.')

# --- Работа с зашифрованной базой ---
def decrypt_db(key: bytes):
    if os.path.exists(ENCRYPTED_DB):
        f    = Fernet(key)
        data = f.decrypt(open(ENCRYPTED_DB,'rb').read())
        open(PLAIN_DB,'wb').write(data)
    else:
        open(PLAIN_DB,'wb').close()

def encrypt_db(key: bytes):
    f    = Fernet(key)
    data = open(PLAIN_DB,'rb').read()
    open(ENCRYPTED_DB,'wb').write(f.encrypt(data))
    os.remove(PLAIN_DB)

# --- SQLAlchemy модель ---
Base = declarative_base()
class Entry(Base):
    __tablename__ = 'entries'
    id       = Column(Integer, primary_key=True)
    service  = Column(String,  nullable=False)
    login    = Column(String)
    password = Column(String,  nullable=False)
    note     = Column(String)

# --- Менеджер паролей ---
class PasswordManager:
    def __init__(self):
        self.engine  = create_engine(f'sqlite:///{PLAIN_DB}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_entry(self, svc, lg, pwd, note):
        s = self.Session()
        e = Entry(service=svc, login=lg, password=pwd, note=note)
        s.add(e); s.commit(); s.close()

    def delete_entry(self, entry_id: int):
        s = self.Session()
        entry = s.query(Entry).filter(Entry.id == entry_id).first()
        if entry:
            s.delete(entry)
            s.commit()
        s.close()

    def get_entries(self):
        s    = self.Session()
        rows = s.query(Entry).all()
        s.close()
        return rows

# --- Диалог добавления записи ---
class AddDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Новая запись')
        self.svc  = QLineEdit(); self.lg  = QLineEdit()
        self.pw   = QLineEdit(); self.note = QLineEdit()
        gen = QPushButton('Сгенерировать'); gen.clicked.connect(self.gen_pw)
        save = QPushButton('Сохранить');     save.clicked.connect(self.accept)

        lay = QVBoxLayout()
        lay.addWidget(QLabel('Сервис:'));   lay.addWidget(self.svc)
        lay.addWidget(QLabel('Логин:'));     lay.addWidget(self.lg)
        lay.addWidget(QLabel('Пароль:'))
        row = QHBoxLayout(); row.addWidget(self.pw); row.addWidget(gen)
        lay.addLayout(row)
        lay.addWidget(QLabel('Примечание:')); lay.addWidget(self.note)
        lay.addWidget(save); self.setLayout(lay)

    def gen_pw(self):
        length, ok = QInputDialog.getInt(self,'Длина','Укажите длину:',16,6,64)
        if not ok: return
        r = 3.99; x = time.time()%1
        chars = string.ascii_letters+string.digits+string.punctuation
        pwd = ''
        for _ in range(length):
            x   = r*x*(1-x)
            idx = int(abs(x)*len(chars))%len(chars)
            pwd += chars[idx]
        self.pw.setText(pwd)

# --- Главное окно ---
class MainWindow(QMainWindow):
    def __init__(self, pm: PasswordManager, key: bytes):
        super().__init__()
        self.pm = pm
        self.key = key
        self.setWindowTitle('Менеджер паролей v4')

        # меню
        men = QMenuBar(self)
        self.setMenuBar(men)
        acc = men.addMenu('Аккаунт')
        acc.addAction(QAction('Сменить мастер-пароль', self, triggered=lambda: change_master_password(self.key)))

        # Таблица для отображения паролей
        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(['ID', 'Сервис', 'Логин', 'Пароль', 'Примечание'])
        self.tbl.setSelectionMode(QTableWidget.SingleSelection)  # Выбор одного элемента
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)  # Поведение выбора по строкам

        # Кнопки
        btn_add = QPushButton('Добавить запись')
        btn_add.clicked.connect(self.on_add)
        btn_del = QPushButton('Удалить запись')
        btn_del.clicked.connect(self.on_delete)

        # Лейаут
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(self.tbl)
        v.addWidget(btn_add)
        v.addWidget(btn_del)

        self.setCentralWidget(w)
        self.load()

    def load(self):
        rows = self.pm.get_entries()
        self.tbl.setRowCount(len(rows))
        for i, e in enumerate(rows):
            self.tbl.setItem(i, 0, QTableWidgetItem(str(e.id)))
            self.tbl.setItem(i, 1, QTableWidgetItem(e.service))
            self.tbl.setItem(i, 2, QTableWidgetItem(e.login or ''))
            self.tbl.setItem(i, 3, QTableWidgetItem(e.password))
            self.tbl.setItem(i, 4, QTableWidgetItem(e.note or ''))

    def on_add(self):
        dlg = AddDialog()
        if dlg.exec():
            svc = dlg.svc.text().strip()
            pwd = dlg.pw.text().strip()
            if not svc or not pwd:
                QMessageBox.warning(self, 'Ошибка', 'Сервис и пароль обязательны')
                return
            self.pm.add_entry(svc, dlg.lg.text().strip(), pwd, dlg.note.text().strip())
            self.load()

    def on_delete(self):
        row = self.tbl.currentRow()
        if row == -1:
            QMessageBox.warning(self, 'Ошибка', 'Выберите запись для удаления')
            return

        # Подтверждение удаления
        entry_id = int(self.tbl.item(row, 0).text())
        reply = QMessageBox.question(self, 'Подтверждение удаления',
                                     f'Вы уверены, что хотите удалить запись {entry_id}?', 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.pm.delete_entry(entry_id)
            self.load()

# --- Точка входа ---
def main():
    app = QApplication(sys.argv)

    # 1) Конфиг и проверка
    init_config()
    key = check_master_password()

    # 2) Дешифруем базу
    decrypt_db(key)

    # 3) UI
    pm = PasswordManager()
    mw = MainWindow(pm, key)
    mw.resize(800,450); mw.show()
    ret = app.exec()

    # 4) Шифруем перед выходом
    encrypt_db(key)
    sys.exit(ret)

if __name__ == '__main__':
    main()

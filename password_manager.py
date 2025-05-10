# Менеджер паролей v3 (русский интерфейс, вход по паролю, математическая модель)
# Требования: PySide6, SQLAlchemy
# Установка:
#   pip install -r requirements.txt

import sys
import os
import time
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QPushButton, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QLabel, QDialog, QMessageBox, QInputDialog
)
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

# --- Модель базы данных ---
Base = declarative_base()
class Entry(Base):
    __tablename__ = 'entries'
    id = Column(Integer, primary_key=True)
    service = Column(String, nullable=False)
    login = Column(String)
    password = Column(String, nullable=False)
    note = Column(String)

# --- Менеджер паролей ---
class PasswordManager:
    def __init__(self):
        db_path = os.path.join(os.path.dirname(__file__), 'passwords.db')
        self.engine = create_engine(f'sqlite:///{db_path}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_entry(self, service, login, password, note):
        session = self.Session()
        entry = Entry(service=service, login=login, password=password, note=note)
        session.add(entry)
        session.commit()
        session.close()

    def get_entries(self):
        session = self.Session()
        entries = session.query(Entry).all()
        session.close()
        return entries

# --- Диалог добавления записи ---
class AddDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Новая запись')
        self.service_input = QLineEdit()
        self.login_input = QLineEdit()
        self.password_input = QLineEdit()
        self.note_input = QLineEdit()

        gen_btn = QPushButton('Сгенерировать пароль')
        gen_btn.clicked.connect(self.generate_password)
        save_btn = QPushButton('Сохранить')
        save_btn.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(QLabel('Сервис:'))
        layout.addWidget(self.service_input)
        layout.addWidget(QLabel('Логин:'))
        layout.addWidget(self.login_input)
        layout.addWidget(QLabel('Пароль:'))
        pw_layout = QHBoxLayout()
        pw_layout.addWidget(self.password_input)
        pw_layout.addWidget(gen_btn)
        layout.addLayout(pw_layout)
        layout.addWidget(QLabel('Примечание:'))
        layout.addWidget(self.note_input)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def generate_password(self):
        length, ok = QInputDialog.getInt(self, 'Длина пароля', 'Укажите длину:', 16, 6, 64)
        if not ok:
            return
        # Математическая модель (катастрофическая карта Ляпунова)
        import math, string
        # r-параметр для логистической карты
        r = 3.99
        # начальное значение из текущего времени
        x = time.time() % 1
        chars = string.ascii_letters + string.digits + string.punctuation
        pwd = ''
        for _ in range(length):
            x = r * x * (1 - x)
            idx = int(abs(x) * len(chars)) % len(chars)
            pwd += chars[idx]
        self.password_input.setText(pwd)

# --- Главное окно ---
class MainWindow(QMainWindow):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.setWindowTitle('Менеджер паролей v3')

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['ID', 'Сервис', 'Логин', 'Пароль', 'Примечание'])
        self.load_entries()

        add_btn = QPushButton('Добавить запись')
        add_btn.clicked.connect(self.add_entry)

        container = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        layout.addWidget(add_btn)
        container.setLayout(layout)
        self.setCentralWidget(container)

    def load_entries(self):
        entries = self.manager.get_entries()
        self.table.setRowCount(len(entries))
        for i, e in enumerate(entries):
            self.table.setItem(i, 0, QTableWidgetItem(str(e.id)))
            self.table.setItem(i, 1, QTableWidgetItem(e.service))
            self.table.setItem(i, 2, QTableWidgetItem(e.login or ''))
            self.table.setItem(i, 3, QTableWidgetItem(e.password))
            self.table.setItem(i, 4, QTableWidgetItem(e.note or ''))

    def add_entry(self):
        dlg = AddDialog()
        if dlg.exec():
            svc = dlg.service_input.text().strip()
            pwd = dlg.password_input.text().strip()
            if not svc or not pwd:
                QMessageBox.warning(self, 'Ошибка', 'Сервис и пароль обязательны')
                return
            lg = dlg.login_input.text().strip()
            note = dlg.note_input.text().strip()
            self.manager.add_entry(svc, lg, pwd, note)
            self.load_entries()

def main():
    app = QApplication(sys.argv)
    # Запрос пароля при входе
    passwd, ok = QInputDialog.getText(None, 'Авторизация', 'Введите пароль для входа:', QLineEdit.Password)
    if not ok or passwd != '123321':
        QMessageBox.critical(None, 'Ошибка', 'Неверный пароль, доступ запрещён.')
        sys.exit()

    manager = PasswordManager()
    win = MainWindow(manager)
    win.resize(800, 450)
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()

import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QMessageBox, QInputDialog
)
from .api_client import APIClient

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("License Admin (Basic)")
        self.resize(920, 540)

        self.api = None

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        # Login row
        row1 = QHBoxLayout()
        layout.addLayout(row1)

        self.ed_server = QLineEdit("https://YOUR-RENDER.onrender.com")
        self.ed_user = QLineEdit("admin")
        self.ed_pass = QLineEdit("")
        self.ed_pass.setEchoMode(QLineEdit.Password)

        btn_login = QPushButton("Login")
        btn_login.clicked.connect(self.on_login)

        row1.addWidget(QLabel("Server:"))
        row1.addWidget(self.ed_server, 3)
        row1.addWidget(QLabel("User:"))
        row1.addWidget(self.ed_user, 1)
        row1.addWidget(QLabel("Pass:"))
        row1.addWidget(self.ed_pass, 1)
        row1.addWidget(btn_login)

        # Actions
        row2 = QHBoxLayout()
        layout.addLayout(row2)

        self.ed_search = QLineEdit("")
        self.ed_search.setPlaceholderText("Search by tail (last 8 chars)...")

        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.reload)

        btn_create = QPushButton("Create")
        btn_create.clicked.connect(self.create_license)

        btn_extend = QPushButton("Extend")
        btn_extend.clicked.connect(self.extend_license)

        btn_revoke = QPushButton("Revoke")
        btn_revoke.clicked.connect(self.revoke_license)

        btn_acts = QPushButton("Activations")
        btn_acts.clicked.connect(self.show_activations)

        row2.addWidget(self.ed_search, 2)
        row2.addWidget(btn_refresh)
        row2.addWidget(btn_create)
        row2.addWidget(btn_extend)
        row2.addWidget(btn_revoke)
        row2.addWidget(btn_acts)

        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "ID", "TAIL", "STATUS", "EXPIRES", "MAX", "ACTS", "NOTE"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def _need_login(self):
        if not self.api or not self.api.token:
            QMessageBox.warning(self, "Login", "Please login first.")
            return True
        return False

    def on_login(self):
        try:
            self.api = APIClient(self.ed_server.text().strip())
            self.api.login(self.ed_user.text().strip(), self.ed_pass.text())
            QMessageBox.information(self, "OK", "Login success")
            self.reload()
        except Exception as e:
            QMessageBox.critical(self, "Login failed", str(e))

    def reload(self):
        if self._need_login():
            return
        try:
            q = self.ed_search.text().strip()
            data = self.api.list_licenses(q=q)
            self.table.setRowCount(0)
            for item in data:
                r = self.table.rowCount()
                self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(item["id"]))
                self.table.setItem(r, 1, QTableWidgetItem(item["key_tail"]))
                self.table.setItem(r, 2, QTableWidgetItem(item["status"]))
                self.table.setItem(r, 3, QTableWidgetItem(item["expires_at"]))
                self.table.setItem(r, 4, QTableWidgetItem(str(item["max_activations"])))
                self.table.setItem(r, 5, QTableWidgetItem(str(item["activations_count"])))
                self.table.setItem(r, 6, QTableWidgetItem(item.get("note", "")))
            self.table.resizeColumnsToContents()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _selected_license_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        return self.table.item(row, 0).text()

    def create_license(self):
        if self._need_login():
            return
        try:
            days, ok = QInputDialog.getInt(self, "Create", "Days:", 30, 1, 3650)
            if not ok:
                return
            maxa, ok = QInputDialog.getInt(self, "Create", "Max activations:", 1, 1, 50)
            if not ok:
                return
            note, ok = QInputDialog.getText(self, "Create", "Note (optional):")
            if not ok:
                note = ""
            res = self.api.create_license(days=days, max_activations=maxa, note=note)
            key = res["license_key"]
            QMessageBox.information(self, "Created", f"LICENSE KEY (copy now):\n{key}\n\n*Server chỉ lưu hash nên bạn sẽ không xem lại key đầy đủ sau này.")
            self.reload()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def revoke_license(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QMessageBox.warning(self, "Select", "Select a license row first.")
            return
        try:
            self.api.revoke_license(lid)
            QMessageBox.information(self, "OK", "Revoked")
            self.reload()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def extend_license(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QMessageBox.warning(self, "Select", "Select a license row first.")
            return
        try:
            days, ok = QInputDialog.getInt(self, "Extend", "Days to add:", 30, 1, 3650)
            if not ok:
                return
            self.api.extend_license(lid, days)
            QMessageBox.information(self, "OK", "Extended")
            self.reload()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def show_activations(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QMessageBox.warning(self, "Select", "Select a license row first.")
            return
        try:
            acts = self.api.list_activations(lid)
            text = "\n".join([f"{a['id']} | {a['machine_id']} | revoked={a.get('revoked_at')}" for a in acts]) or "(none)"
            QMessageBox.information(self, "Activations", text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

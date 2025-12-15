import sys
import csv
import requests
from typing import Any, Dict, List, Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from .api_client import APIClient
from .vault import load_vault, save_vault, upsert_license_key, get_license_key
from .utils import fmt_iso_to_local


# =========================
# Small dialogs
# =========================
class CreateLicenseDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Tạo license")
        self.resize(520, 220)

        layout = QtWidgets.QVBoxLayout(self)

        form = QtWidgets.QFormLayout()
        self.sp_days = QtWidgets.QSpinBox()
        self.sp_days.setRange(1, 3650)
        self.sp_days.setValue(30)

        self.sp_max = QtWidgets.QSpinBox()
        self.sp_max.setRange(1, 50)
        self.sp_max.setValue(1)

        self.ed_note = QtWidgets.QLineEdit()
        self.ed_custom = QtWidgets.QLineEdit()
        self.ed_custom.setPlaceholderText("(tuỳ chọn) nhập custom key, để trống = server tự sinh")

        form.addRow("Days:", self.sp_days)
        form.addRow("Max activations:", self.sp_max)
        form.addRow("Note:", self.ed_note)
        form.addRow("Custom key:", self.ed_custom)
        layout.addLayout(form)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def data(self) -> Dict[str, Any]:
        return {
            "days": int(self.sp_days.value()),
            "max_activations": int(self.sp_max.value()),
            "note": self.ed_note.text().strip(),
            "custom_key": self.ed_custom.text().strip() or None,
        }


class EditLicenseDialog(QtWidgets.QDialog):
    def __init__(self, current: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sửa license")
        self.resize(560, 260)

        layout = QtWidgets.QVBoxLayout(self)

        hint = QtWidgets.QLabel(
            "Lưu ý: Server KHÔNG lưu full license key (chỉ lưu hash + key_tail), "
            "nên không thể sửa chuỗi key.\n"
            "Bạn chỉ nên sửa: status / expires_at / max_activations / note."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QtWidgets.QFormLayout()

        self.cbo_status = QtWidgets.QComboBox()
        self.cbo_status.addItems(["active", "revoked", "disabled", "deleted"])
        st = (current.get("status") or "active").lower()
        if st in ("active", "revoked", "disabled", "deleted"):
            self.cbo_status.setCurrentText(st)

        self.ed_expires = QtWidgets.QLineEdit(str(current.get("expires_at") or ""))
        self.ed_expires.setPlaceholderText("ISO (Z ok), ví dụ: 2026-01-13T10:00:00Z")

        self.sp_max = QtWidgets.QSpinBox()
        self.sp_max.setRange(1, 50)
        self.sp_max.setValue(int(current.get("max_activations") or 1))

        self.ed_note = QtWidgets.QLineEdit(str(current.get("note") or ""))

        form.addRow("Status:", self.cbo_status)
        form.addRow("Expires at (ISO):", self.ed_expires)
        form.addRow("Max activations:", self.sp_max)
        form.addRow("Note:", self.ed_note)
        layout.addLayout(form)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def data(self) -> Dict[str, Any]:
        # Nếu user để trống expires_at => không update expires_at
        expires = self.ed_expires.text().strip()
        return {
            "status": self.cbo_status.currentText().strip(),
            "expires_at": expires if expires else None,
            "max_activations": int(self.sp_max.value()),
            "note": self.ed_note.text().strip(),
        }


# =========================
# Main window
# =========================
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ToolTongHop - License Admin")
        self.resize(1250, 720)

        self.api: Optional[APIClient] = None
        self._licenses_cache: List[Dict[str, Any]] = []

        self._build_ui()
        self._set_authed(False)

    # ---------- UI ----------
    def _build_ui(self):
        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        layout = QtWidgets.QVBoxLayout(root)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Top row: server + health + public key
        row0 = QtWidgets.QHBoxLayout()
        self.ed_server = QtWidgets.QLineEdit("https://YOUR-RENDER.onrender.com")
        self.ed_server.setPlaceholderText("https://tooltonghop.onrender.com")

        self.btn_health = QtWidgets.QPushButton("Wake / Health")
        self.lbl_health = QtWidgets.QLabel("—")
        self.lbl_health.setMinimumWidth(180)

        self.btn_pubkey = QtWidgets.QPushButton("Public key")

        row0.addWidget(QtWidgets.QLabel("Server:"))
        row0.addWidget(self.ed_server, 2)
        row0.addWidget(self.btn_health)
        row0.addWidget(self.lbl_health)
        row0.addStretch(1)
        row0.addWidget(self.btn_pubkey)
        layout.addLayout(row0)

        # Login row
        row1 = QtWidgets.QHBoxLayout()
        self.ed_user = QtWidgets.QLineEdit("admin")
        self.ed_pass = QtWidgets.QLineEdit("")
        self.ed_pass.setEchoMode(QtWidgets.QLineEdit.Password)

        self.btn_login = QtWidgets.QPushButton("Login")
        self.btn_logout = QtWidgets.QPushButton("Logout")
        self.lbl_auth = QtWidgets.QLabel("Chưa login")

        row1.addWidget(QtWidgets.QLabel("User:"))
        row1.addWidget(self.ed_user, 1)
        row1.addWidget(QtWidgets.QLabel("Pass:"))
        row1.addWidget(self.ed_pass, 1)
        row1.addWidget(self.btn_login)
        row1.addWidget(self.btn_logout)
        row1.addWidget(self.lbl_auth)
        row1.addStretch(1)
        layout.addLayout(row1)

        # Search + actions
        row2 = QtWidgets.QHBoxLayout()
        self.ed_search = QtWidgets.QLineEdit("")
        self.ed_search.setPlaceholderText("Search: id / key_tail / status / note ... (Enter để tìm)")

        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_create = QtWidgets.QPushButton("Tạo")
        self.btn_edit = QtWidgets.QPushButton("Sửa")
        self.btn_extend = QtWidgets.QPushButton("Gia hạn")
        self.btn_revoke = QtWidgets.QPushButton("Revoke")
        self.btn_delete = QtWidgets.QPushButton("Xoá")
        self.btn_export = QtWidgets.QPushButton("Export CSV")

        row2.addWidget(self.ed_search, 2)
        row2.addWidget(self.btn_refresh)
        row2.addWidget(self.btn_create)
        row2.addWidget(self.btn_edit)
        row2.addWidget(self.btn_extend)
        row2.addWidget(self.btn_revoke)
        row2.addWidget(self.btn_delete)
        row2.addStretch(1)
        row2.addWidget(self.btn_export)
        layout.addLayout(row2)

        # Key local tools
        row3 = QtWidgets.QHBoxLayout()
        self.btn_copy_key = QtWidgets.QPushButton("Copy key")
        self.btn_import_key = QtWidgets.QPushButton("Nhập key")
        self.btn_edit_local_key = QtWidgets.QPushButton("Sửa key (local)")
        self.btn_delete_local_key = QtWidgets.QPushButton("Xoá key (local)")
        self.lbl_key_local = QtWidgets.QLabel("Key local: —")
        f = self.lbl_key_local.font()
        f.setBold(True)
        self.lbl_key_local.setFont(f)

        row3.addWidget(self.btn_copy_key)
        row3.addWidget(self.btn_import_key)
        row3.addWidget(self.btn_edit_local_key)
        row3.addWidget(self.btn_delete_local_key)
        row3.addStretch(1)
        row3.addWidget(self.lbl_key_local)
        layout.addLayout(row3)

        # Splitter: licenses / activations
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: licenses table
        left = QtWidgets.QWidget()
        lyt_left = QtWidgets.QVBoxLayout(left)
        lyt_left.setContentsMargins(6, 6, 6, 6)

        self.tbl_lic = QtWidgets.QTableWidget(0, 8)
        self.tbl_lic.setHorizontalHeaderLabels(
            ["id", "key_tail", "status", "expires_at", "max_act", "act_count", "created_at", "note"]
        )
        self.tbl_lic.horizontalHeader().setStretchLastSection(True)
        self.tbl_lic.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_lic.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.tbl_lic.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_lic.setAlternatingRowColors(True)
        self.tbl_lic.verticalHeader().setVisible(False)

        lyt_left.addWidget(self.tbl_lic, 1)
        splitter.addWidget(left)

        # Right: activations table
        right = QtWidgets.QWidget()
        lyt_right = QtWidgets.QVBoxLayout(right)
        lyt_right.setContentsMargins(6, 6, 6, 6)
        lyt_right.setSpacing(8)

        row_act = QtWidgets.QHBoxLayout()
        self.lbl_selected = QtWidgets.QLabel("Chọn 1 license để xem activations")
        f2 = self.lbl_selected.font()
        f2.setBold(True)
        self.lbl_selected.setFont(f2)

        self.btn_act_refresh = QtWidgets.QPushButton("Refresh activations")
        self.btn_act_revoke = QtWidgets.QPushButton("Revoke activation")
        self.btn_copy_machine = QtWidgets.QPushButton("Copy machine_id")

        row_act.addWidget(self.lbl_selected)
        row_act.addStretch(1)
        row_act.addWidget(self.btn_act_refresh)
        row_act.addWidget(self.btn_act_revoke)
        row_act.addWidget(self.btn_copy_machine)
        lyt_right.addLayout(row_act)

        self.tbl_act = QtWidgets.QTableWidget(0, 5)
        self.tbl_act.setHorizontalHeaderLabels(["id", "machine_id", "created_at", "last_checkin_at", "revoked_at"])
        self.tbl_act.horizontalHeader().setStretchLastSection(True)
        self.tbl_act.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_act.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.tbl_act.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_act.setAlternatingRowColors(True)
        self.tbl_act.verticalHeader().setVisible(False)

        lyt_right.addWidget(self.tbl_act, 1)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

        # Status bar
        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)

        # Signals
        self.btn_health.clicked.connect(self.on_health)
        self.btn_pubkey.clicked.connect(self.on_pubkey)

        self.btn_login.clicked.connect(self.on_login)
        self.btn_logout.clicked.connect(self.on_logout)

        self.btn_refresh.clicked.connect(self.reload)
        self.btn_create.clicked.connect(self.create_license)
        self.btn_edit.clicked.connect(self.edit_license)
        self.btn_extend.clicked.connect(self.extend_license)
        self.btn_revoke.clicked.connect(self.revoke_license)
        self.btn_delete.clicked.connect(self.delete_license)
        self.btn_export.clicked.connect(self.export_csv)

        self.btn_copy_key.clicked.connect(self.copy_license_key)
        self.btn_import_key.clicked.connect(self.import_license_key)
        self.btn_edit_local_key.clicked.connect(self.edit_local_key)
        self.btn_delete_local_key.clicked.connect(self.delete_local_key)

        self.ed_search.returnPressed.connect(self.reload)

        self.tbl_lic.itemSelectionChanged.connect(self.on_license_selected)
        self.tbl_lic.cellDoubleClicked.connect(lambda *_: self.edit_license())

        self.btn_act_refresh.clicked.connect(self.refresh_activations)
        self.btn_act_revoke.clicked.connect(self.revoke_activation)
        self.btn_copy_machine.clicked.connect(self.copy_machine_id)

    def _toast(self, msg: str):
        self.status.showMessage(msg, 8000)

    def _set_authed(self, authed: bool):
        self.btn_login.setEnabled(not authed)
        self.btn_logout.setEnabled(authed)

        for b in (
            self.btn_refresh, self.btn_create, self.btn_edit, self.btn_extend,
            self.btn_revoke, self.btn_delete, self.btn_export,
            self.btn_copy_key, self.btn_import_key, self.btn_edit_local_key, self.btn_delete_local_key,
            self.btn_act_refresh, self.btn_act_revoke, self.btn_copy_machine
        ):
            b.setEnabled(authed)

        self.lbl_auth.setText("Đã login" if authed else "Chưa login")

    def _need_login(self) -> bool:
        if not self.api or not self.api.token:
            QtWidgets.QMessageBox.warning(self, "Login", "Vui lòng login trước.")
            return True
        return False

    def _base_url(self) -> str:
        return self.ed_server.text().strip().rstrip("/")

    # ---------- Top actions ----------
    def on_health(self):
        try:
            url = self._base_url() + "/health"
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            data = r.json()
            self.lbl_health.setText(f"OK {data.get('time','')}")
            self._toast("Server OK")
        except Exception as e:
            self.lbl_health.setText("ERROR")
            QtWidgets.QMessageBox.critical(self, "Health failed", str(e))

    def on_pubkey(self):
        try:
            url = self._base_url() + "/v1/public-keys"
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            data = r.json()
            pk = data.get("public_key_b64", "") or ""
            QtWidgets.QApplication.clipboard().setText(pk)
            QtWidgets.QMessageBox.information(self, "Public key", f"kid: {data.get('kid','')}\nĐã copy public_key_b64.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Public key failed", str(e))

    # ---------- Auth ----------
    def on_login(self):
        try:
            self.api = APIClient(self._base_url())
            self.api.login(self.ed_user.text().strip(), self.ed_pass.text())
            self._set_authed(True)
            self._toast("Login OK")
            self.reload()
        except Exception as e:
            self._set_authed(False)
            QtWidgets.QMessageBox.critical(self, "Login failed", str(e))

    def on_logout(self):
        if self.api:
            self.api.token = None
        self._licenses_cache = []
        self.tbl_lic.setRowCount(0)
        self.tbl_act.setRowCount(0)
        self.lbl_selected.setText("Chọn 1 license để xem activations")
        self.lbl_key_local.setText("Key local: —")
        self._set_authed(False)
        self._toast("Logged out")

    # ---------- License table ----------
    def reload(self):
        if self._need_login():
            return
        try:
            q = self.ed_search.text().strip()
            data = self.api.list_licenses(q=q)
            if not isinstance(data, list):
                raise RuntimeError(f"Unexpected response: {data}")

            self._licenses_cache = data
            self.tbl_lic.setRowCount(0)

            for item in data:
                r = self.tbl_lic.rowCount()
                self.tbl_lic.insertRow(r)

                # raw fields (keep for edit)
                lic_id = item.get("id", "")
                key_tail = item.get("key_tail", "")
                status = item.get("status", "")
                expires_raw = item.get("expires_at", "")
                created_raw = item.get("created_at", "")

                cells = [
                    str(lic_id),
                    str(key_tail),
                    str(status),
                    fmt_iso_to_local(expires_raw),
                    str(item.get("max_activations", "")),
                    str(item.get("activations_count", "")),
                    fmt_iso_to_local(created_raw),
                    str(item.get("note", "") or ""),
                ]

                for c, v in enumerate(cells):
                    it = QtWidgets.QTableWidgetItem(v)
                    if c == 0:
                        it.setData(QtCore.Qt.UserRole, item)  # store full dict on id cell
                    self.tbl_lic.setItem(r, c, it)

            self.tbl_lic.resizeColumnsToContents()
            self._toast(f"Loaded {len(data)} licenses")

            # clear activations if no selection
            if self.tbl_lic.currentRow() < 0 and self.tbl_lic.rowCount() > 0:
                self.tbl_lic.selectRow(0)

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

    def _selected_license_item(self) -> Optional[Dict[str, Any]]:
        row = self.tbl_lic.currentRow()
        if row < 0:
            return None
        cell = self.tbl_lic.item(row, 0)
        if not cell:
            return None
        item = cell.data(QtCore.Qt.UserRole)
        return item if isinstance(item, dict) else None

    def _selected_license_id(self) -> Optional[str]:
        item = self._selected_license_item()
        return str(item.get("id")) if item else None

    def _selected_tail(self) -> str:
        item = self._selected_license_item()
        return str(item.get("key_tail") or "") if item else ""

    def on_license_selected(self):
        lic_id = self._selected_license_id()
        if not lic_id:
            return
        self.lbl_selected.setText(f"License: {lic_id}")
        self._update_local_key_badge()
        self.refresh_activations()

    # ---------- CRUD License ----------
    def create_license(self):
        if self._need_login():
            return
        dlg = CreateLicenseDialog(self)
        if dlg.exec_() != QtWidgets.QDialog.Accepted:
            return

        try:
            d = dlg.data()
            res = self.api.create_license(
                days=d["days"],
                max_activations=d["max_activations"],
                note=d["note"],
                custom_key=d["custom_key"],
            )

            key = res.get("license_key") or ""
            lic = res.get("license") or {}
            lic_id = lic.get("id")

            if lic_id and key:
                upsert_license_key(str(lic_id), key)
                QtWidgets.QApplication.clipboard().setText(key)

            QtWidgets.QMessageBox.information(
                self,
                "Created",
                f"LICENSE KEY (đã copy):\n{key}\n\n"
                "*Server chỉ lưu hash + key_tail nên bạn sẽ không xem lại key đầy đủ sau này.\n"
                "Key full đã được lưu local để bạn Copy về sau.",
            )
            self.reload()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

    def edit_license(self):
        if self._need_login():
            return
        cur = self._selected_license_item()
        if not cur:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return

        dlg = EditLicenseDialog(cur, self)
        if dlg.exec_() != QtWidgets.QDialog.Accepted:
            return

        try:
            d = dlg.data()
            lid = str(cur["id"])

            self.api.update_license(
                lid,
                status=d["status"],
                expires_at=d["expires_at"],
                max_activations=d["max_activations"],
                note=d["note"],
            )
            self._toast("Updated")
            self.reload()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Update failed", str(e))

    def delete_license(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return

        if QtWidgets.QMessageBox.question(
            self,
            "Xoá license",
            f"Bạn chắc chắn muốn XOÁ license này?\n\n{lid}\n\n"
            "Xoá ở đây là xoá mềm (status=deleted) và revoke activations.",
        ) != QtWidgets.QMessageBox.Yes:
            return

        try:
            self.api.delete_license(lid)
            self._delete_local_key_by_id(lid)  # dọn local key nếu có
            self._toast("Deleted")
            self.reload()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Delete failed", str(e))

    def revoke_license(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return
        try:
            self.api.revoke_license(lid)
            self._toast("Revoked")
            self.reload()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

    def extend_license(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return
        try:
            days, ok = QtWidgets.QInputDialog.getInt(self, "Gia hạn", "Days to add:", 30, 1, 3650)
            if not ok:
                return
            self.api.extend_license(lid, days)
            self._toast("Extended")
            self.reload()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

    # ---------- Local key ----------
    def _update_local_key_badge(self):
        lid = self._selected_license_id()
        if not lid:
            self.lbl_key_local.setText("Key local: —")
            return
        self.lbl_key_local.setText("Key local: ✅" if get_license_key(lid) else "Key local: ❌")

    def _delete_local_key_by_id(self, license_id: str) -> bool:
        items = load_vault()
        if str(license_id) in items:
            items.pop(str(license_id), None)
            save_vault(items)
            return True
        return False

    def copy_license_key(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return

        key = get_license_key(lid)
        if key:
            QtWidgets.QApplication.clipboard().setText(key)
            self._toast("Copied license key")
            return

        tail = self._selected_tail()
        if tail:
            QtWidgets.QApplication.clipboard().setText(tail)

        QtWidgets.QMessageBox.warning(
            self,
            "Không có full license key",
            "Server không lưu full key nên không thể lấy lại từ danh sách.\n"
            "Bạn hãy dùng 'Nhập key' (nếu bạn còn lưu) hoặc tạo license mới.\n\n"
            + (f"(Đã copy key_tail: {tail})" if tail else "")
        )

    def import_license_key(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return

        tail_expected = self._selected_tail()
        text, ok = QtWidgets.QInputDialog.getText(
            self, "Nhập key", "Dán full license key (sẽ lưu local để copy nhanh):"
        )
        if not ok:
            return
        key = (text or "").strip()
        if not key:
            return

        if tail_expected and not key.endswith(tail_expected):
            if QtWidgets.QMessageBox.question(
                self,
                "Key không khớp",
                f"Key bạn nhập không kết thúc bằng key_tail ({tail_expected}).\nVẫn lưu key này?",
            ) != QtWidgets.QMessageBox.Yes:
                return

        upsert_license_key(lid, key)
        QtWidgets.QApplication.clipboard().setText(key)
        self._toast("Imported + copied")
        self._update_local_key_badge()

    def edit_local_key(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return

        current = get_license_key(lid) or ""
        text, ok = QtWidgets.QInputDialog.getText(
            self, "Sửa key (local)", "Dán full license key:", text=current
        )
        if not ok:
            return
        key = (text or "").strip()
        if not key:
            return

        upsert_license_key(lid, key)
        QtWidgets.QApplication.clipboard().setText(key)
        self._toast("Saved local key + copied")
        self._update_local_key_badge()

    def delete_local_key(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 license trước.")
            return

        if QtWidgets.QMessageBox.question(
            self, "Xoá key (local)", "Xoá full key đã lưu local? (Không ảnh hưởng server)"
        ) != QtWidgets.QMessageBox.Yes:
            return

        ok = self._delete_local_key_by_id(lid)
        self._toast("Deleted local key" if ok else "No local key")
        self._update_local_key_badge()

    # ---------- Activations ----------
    def refresh_activations(self):
        if self._need_login():
            return
        lid = self._selected_license_id()
        if not lid:
            return
        try:
            acts = self.api.list_activations(lid)
            if not isinstance(acts, list):
                raise RuntimeError(f"Unexpected response: {acts}")

            self.tbl_act.setRowCount(0)
            for a in acts:
                r = self.tbl_act.rowCount()
                self.tbl_act.insertRow(r)
                vals = [
                    str(a.get("id", "")),
                    str(a.get("machine_id", "")),
                    fmt_iso_to_local(a.get("created_at", "")),
                    fmt_iso_to_local(a.get("last_checkin_at", "")),
                    fmt_iso_to_local(a.get("revoked_at", "")) if a.get("revoked_at") else "",
                ]
                for c, v in enumerate(vals):
                    self.tbl_act.setItem(r, c, QtWidgets.QTableWidgetItem(v))

            self.tbl_act.resizeColumnsToContents()
            self._toast(f"Loaded {len(acts)} activations")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Activations failed", str(e))

    def _selected_activation_id(self) -> Optional[str]:
        row = self.tbl_act.currentRow()
        if row < 0:
            return None
        it = self.tbl_act.item(row, 0)
        return it.text() if it else None

    def revoke_activation(self):
        if self._need_login():
            return
        aid = self._selected_activation_id()
        if not aid:
            QtWidgets.QMessageBox.warning(self, "Select", "Chọn 1 activation trước.")
            return
        if QtWidgets.QMessageBox.question(self, "Revoke activation", f"Revoke activation {aid}?") != QtWidgets.QMessageBox.Yes:
            return
        try:
            self.api.revoke_activation(aid)
            self._toast("Activation revoked")
            self.refresh_activations()
            self.reload()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Revoke activation failed", str(e))

    def copy_machine_id(self):
        row = self.tbl_act.currentRow()
        if row < 0:
            QtWidgets.QMessageBox.information(self, "Copy", "Chọn 1 activation để copy machine_id.")
            return
        it = self.tbl_act.item(row, 1)
        mid = it.text() if it else ""
        if not mid:
            return
        QtWidgets.QApplication.clipboard().setText(mid)
        self._toast("Copied machine_id")

    # ---------- Export ----------
    def export_csv(self):
        if self._need_login():
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export CSV", "licenses.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            items = self._licenses_cache
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=["id", "key_tail", "status", "expires_at", "max_activations", "activations_count", "created_at", "note"],
                )
                w.writeheader()
                for it in items:
                    w.writerow(it)
            self._toast(f"Exported {len(items)} licenses")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(e))


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

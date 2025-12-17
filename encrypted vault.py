import os
import io
import zipfile
import hashlib
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from tkinter import ttk

HEADER = "PVLT1"
SALT_LEN = 16


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _derive_keystream(password: str, salt: bytes, length: int) -> bytes:
    pwb = password.encode("utf-8")
    block = salt + pwb
    out = b""
    counter = 0
    while len(out) < length:
        out += _sha256(block + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    ks = _derive_keystream(password, salt, len(plaintext))
    cipher = bytes(a ^ b for a, b in zip(plaintext, ks))
    payload = HEADER + "\n" + salt.hex() + "\n" + cipher.hex()
    return payload.encode("utf-8")


def decrypt_bytes(data: bytes, password: str) -> bytes:
    try:
        s = data.decode("utf-8")
        h, salt_hex, cipher_hex = s.split("\n", 2)
        if h != HEADER:
            raise ValueError("Not a valid vault")
        salt = bytes.fromhex(salt_hex)
        cipher = bytes.fromhex(cipher_hex)
        ks = _derive_keystream(password, salt, len(cipher))
        plain = bytes(a ^ b for a, b in zip(cipher, ks))
        return plain
    except Exception:
        raise ValueError("Decryption failed")


def create_zip_bytes(file_paths):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in file_paths:
            arcname = os.path.basename(path) or path
            zf.write(path, arcname=arcname)
    return bio.getvalue()


def encrypt_zip_bytes(zip_bytes: bytes, password: str) -> bytes:
    return encrypt_bytes(zip_bytes, password)


def decrypt_vault_bytes(vault_bytes: bytes, password: str) -> bytes:
    return decrypt_bytes(vault_bytes, password)


class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encrypted Vault")
        self.geometry("700x420")
        self.file_list = []
        self.opened_zip_bytes = None
        self.opened_zip_names = []
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=8, pady=8)

        self.lb = tk.Listbox(frm, selectmode=tk.EXTENDED)
        self.lb.pack(side="left", fill="both", expand=True)
        sc = ttk.Scrollbar(frm, command=self.lb.yview)
        sc.pack(side="left", fill="y")
        self.lb.config(yscrollcommand=sc.set)

        btns = ttk.Frame(frm)
        btns.pack(side="right", fill="y", padx=8)
        ttk.Button(btns, text="Add Files...", width=20, command=self.add_files).pack(pady=4)
        ttk.Button(btns, text="Remove Selected", width=20, command=self.remove_selected).pack(pady=4)
        ttk.Separator(btns).pack(fill="x", pady=6)
        ttk.Button(btns, text="Save Vault...", width=20, command=self.save_vault).pack(pady=4)
        ttk.Button(btns, text="Open Vault...", width=20, command=self.open_vault).pack(pady=4)
        ttk.Button(btns, text="Extract Selected...", width=20, command=self.extract_selected).pack(pady=4)
        ttk.Button(btns, text="Clear List", width=20, command=self.clear_list).pack(pady=4)

        hint = ttk.Label(self, text="Tip: Use 'Add Files...' to add files.")
        hint.pack(side="bottom", pady=4)

        try:
            self.tk.call("package", "require", "tkdnd")
        except Exception:
            pass

    def _parse_dnd_paths(self, data):
        parts = []
        cur = ""
        in_brace = False
        for ch in data:
            if ch == "{":
                in_brace = True
                cur = ""
            elif ch == "}":
                in_brace = False
                parts.append(cur)
                cur = ""
            elif ch == " " and not in_brace:
                if cur:
                    parts.append(cur)
                    cur = ""
            else:
                cur += ch
        if cur:
            parts.append(cur)
        return [p for p in parts if os.path.exists(p)]

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Select files to add")
        if paths:
            self.add_files_to_list(self.tk.splitlist(paths))

    def add_files_to_list(self, paths):
        for p in paths:
            if p not in self.file_list:
                self.file_list.append(p)
                self.lb.insert("end", os.path.basename(p))

    def remove_selected(self):
        sel = list(self.lb.curselection())
        sel.sort(reverse=True)
        for i in sel:
            self.lb.delete(i)
            if i < len(self.file_list):
                self.file_list.pop(i)
            if i < len(self.opened_zip_names):
                self.opened_zip_names.pop(i)
        if self.opened_zip_bytes and not self.opened_zip_names:
            self.opened_zip_bytes = None

    def clear_list(self):
        self.lb.delete(0, "end")
        self.file_list = []
        self.opened_zip_bytes = None
        self.opened_zip_names = []

    def save_vault(self):
        if not self.file_list:
            messagebox.showinfo("No files", "No files to save into vault.")
            return
        path = filedialog.asksaveasfilename(
            title="Save vault as", defaultextension=".pvlt", filetypes=[("Vault files", "*.pvlt"), ("All files", "*.*")]
        )
        if not path:
            return
        pwd = simpledialog.askstring("Master password", "Enter master password:", show="*", parent=self)
        if not pwd:
            messagebox.showwarning("Password required", "Master password is required to save vault.")
            return
        pwd2 = simpledialog.askstring("Confirm password", "Confirm master password:", show="*", parent=self)
        if pwd2 != pwd:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return
        try:
            zipb = create_zip_bytes(self.file_list)
            vaultb = encrypt_zip_bytes(zipb, pwd)
            with open(path, "wb") as f:
                f.write(vaultb)
            messagebox.showinfo("Saved", f"Vault saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {e}")

    def open_vault(self):
        path = filedialog.askopenfilename(title="Open vault", filetypes=[("Vault files", "*.pvlt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read file: {e}")
            return
        pwd = simpledialog.askstring("Master password", "Enter master password to open vault:", show="*", parent=self)
        if pwd is None:
            return
        try:
            zipb = decrypt_vault_bytes(data, pwd)
            with zipfile.ZipFile(io.BytesIO(zipb), "r") as zf:
                names = zf.namelist()
            self.lb.delete(0, "end")
            self.opened_zip_bytes = zipb
            self.opened_zip_names = names
            for n in names:
                self.lb.insert("end", n)
            self.file_list = []
            messagebox.showinfo("Opened", f"Vault opened. {len(names)} entries loaded.")
        except Exception as e:
            messagebox.showerror("Decryption failed", f"Could not decrypt vault: {e}")

    def extract_selected(self):
        if not (self.opened_zip_bytes or self.file_list):
            messagebox.showinfo("Nothing to extract", "No opened vault or selected files to extract.")
            return
        outdir = filedialog.askdirectory(title="Select output directory")
        if not outdir:
            return
        try:
            if self.opened_zip_bytes:
                sel = self.lb.curselection()
                if not sel:
                    with zipfile.ZipFile(io.BytesIO(self.opened_zip_bytes), "r") as zf:
                        zf.extractall(outdir)
                else:
                    with zipfile.ZipFile(io.BytesIO(self.opened_zip_bytes), "r") as zf:
                        for i in sel:
                            name = self.opened_zip_names[i]
                            zf.extract(name, outdir)
                messagebox.showinfo("Extracted", f"Files extracted to {outdir}")
                return
            sel = self.lb.curselection()
            indices = sel if sel else range(len(self.file_list))
            for i in indices:
                src = self.file_list[i]
                dst = os.path.join(outdir, os.path.basename(src))
                with open(src, "rb") as r, open(dst, "wb") as w:
                    w.write(r.read())
            messagebox.showinfo("Extracted", f"Files copied to {outdir}")
        except Exception as e:
            messagebox.showerror("Error", f"Extraction failed: {e}")


if __name__ == "__main__":
    app = VaultApp()
    app.mainloop()

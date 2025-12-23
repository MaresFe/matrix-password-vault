import customtkinter as ctk
import os
import json
import base64
import hashlib
import pyperclip # Panoya kopyalamak için
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- AYARLAR VE RENKLER ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green") # Butonlar yeşil olacak

# Hacker Teması Renkleri
COLOR_BG = "#0d0d0d"       # Simsiyah Arka Plan
COLOR_FG = "#00ff41"       # Matrix Yeşili
COLOR_ACCENT = "#003b00"   # Koyu Yeşil
FONT_MAIN = ("Courier", 16, "bold") # Terminal Fontu
DB_FILE = "matrix_vault.json"

# --- BACKEND (Mantık Kısmı) ---
class VaultLogic:
    def __init__(self):
        self.key = None
        self.data = self.load_db()

    def load_db(self):
        if not os.path.exists(DB_FILE):
            return {"salt": None, "master_hash": None, "secrets": {}}
        with open(DB_FILE, "r") as f:
            return json.load(f)

    def save_db(self):
        with open(DB_FILE, "w") as f:
            json.dump(self.data, f, indent=4)

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def register(self, password):
        salt = os.urandom(16)
        self.key = self.derive_key(password, salt)
        master_hash = hashlib.sha256(password.encode()).hexdigest()
        
        self.data["salt"] = base64.b64encode(salt).decode('utf-8')
        self.data["master_hash"] = master_hash
        self.save_db()

    def login(self, password):
        salt = base64.b64decode(self.data["salt"])
        check_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if check_hash == self.data["master_hash"]:
            self.key = self.derive_key(password, salt)
            return True
        return False

    def add_secret(self, site, username, password):
        f = Fernet(self.key)
        encrypted_pwd = f.encrypt(password.encode()).decode()
        self.data["secrets"][site] = {"username": username, "password": encrypted_pwd}
        self.save_db()

    def decrypt_password(self, encrypted_pwd):
        f = Fernet(self.key)
        return f.decrypt(encrypted_pwd.encode()).decode()

# --- FRONTEND (Arayüz Kısmı) ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.logic = VaultLogic()
        
        # Pencere Ayarları
        self.title("HACKER VAULT v1.0")
        self.geometry("600x500")
        self.configure(fg_color=COLOR_BG)
        
        # İlk ekranı belirle
        if self.logic.data["master_hash"] is None:
            self.show_register()
        else:
            self.show_login()

    def clear_screen(self):
        """Ekrandaki her şeyi temizler."""
        for widget in self.winfo_children():
            widget.destroy()

    # --- 1. EKRAN: KAYIT (SETUP) ---
    def show_register(self):
        self.clear_screen()
        
        lbl = ctk.CTkLabel(self, text="[ SISTEM KURULUMU ]", font=("Courier", 24, "bold"), text_color=COLOR_FG)
        lbl.pack(pady=40)
        
        self.entry_reg = ctk.CTkEntry(self, placeholder_text="Yeni Ana Şifre Belirle", 
                                      width=300, show="*", font=FONT_MAIN,
                                      fg_color="#1a1a1a", border_color=COLOR_FG)
        self.entry_reg.pack(pady=10)
        
        btn = ctk.CTkButton(self, text="KURULUMU TAMAMLA", command=self.handle_register,
                            fg_color=COLOR_FG, text_color="black", font=FONT_MAIN, hover_color="#00cc33")
        btn.pack(pady=20)

    def handle_register(self):
        pwd = self.entry_reg.get()
        if pwd:
            self.logic.register(pwd)
            self.show_login()

    # --- 2. EKRAN: GİRİŞ (LOGIN) ---
    def show_login(self):
        self.clear_screen()
        
        lbl = ctk.CTkLabel(self, text="[ GUVENLI GIRIS ]", font=("Courier", 24, "bold"), text_color=COLOR_FG)
        lbl.pack(pady=40)
        
        self.entry_login = ctk.CTkEntry(self, placeholder_text="Ana Şifre", 
                                        width=300, show="*", font=FONT_MAIN,
                                        fg_color="#1a1a1a", border_color=COLOR_FG)
        self.entry_login.pack(pady=10)
        
        self.lbl_error = ctk.CTkLabel(self, text="", text_color="red", font=("Courier", 12))
        self.lbl_error.pack(pady=5)

        btn = ctk.CTkButton(self, text="KILIDI AC", command=self.handle_login,
                            fg_color=COLOR_FG, text_color="black", font=FONT_MAIN, hover_color="#00cc33")
        btn.pack(pady=20)

    def handle_login(self):
        pwd = self.entry_login.get()
        if self.logic.login(pwd):
            self.show_dashboard()
        else:
            self.lbl_error.configure(text="[ERISIM REDDEDILDI] Hatalı Şifre")
            self.entry_login.configure(border_color="red")

    # --- 3. EKRAN: ANA PANEL (DASHBOARD) ---
    def show_dashboard(self):
        self.clear_screen()
        
        # Üst Panel
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=20, pady=10)
        
        lbl = ctk.CTkLabel(top_frame, text="AKTIF KASA", font=("Courier", 20, "bold"), text_color=COLOR_FG)
        lbl.pack(side="left")
        
        btn_add = ctk.CTkButton(top_frame, text="+ EKLE", width=80, command=self.popup_add,
                                fg_color=COLOR_ACCENT, hover_color=COLOR_FG)
        btn_add.pack(side="right")

        # Liste Alanı (Scrollable)
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="#111", label_text="Kayıtlı Şifreler")
        self.scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.refresh_list()

    def refresh_list(self):
        # Listeyi temizle
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
            
        # Listeyi doldur
        for site, info in self.logic.data["secrets"].items():
            row = ctk.CTkFrame(self.scroll_frame, fg_color="#222")
            row.pack(fill="x", pady=5)
            
            lbl_site = ctk.CTkLabel(row, text=f"{site} ({info['username']})", 
                                    font=("Courier", 14), text_color="white")
            lbl_site.pack(side="left", padx=10, pady=10)
            
            # Kopyala Butonu (Lambda fonksiyonu ile veriyi taşıyoruz)
            btn_copy = ctk.CTkButton(row, text="KOPYALA", width=80, 
                                     command=lambda p=info['password']: self.copy_pass(p),
                                     fg_color="transparent", border_width=1, border_color=COLOR_FG)
            btn_copy.pack(side="right", padx=10)

    def copy_pass(self, encrypted_pass):
        decrypted = self.logic.decrypt_password(encrypted_pass)
        pyperclip.copy(decrypted)
        print("Şifre panoya kopyalandı!") # Terminale bilgi verir

    def popup_add(self):
        """Yeni şifre ekleme penceresi"""
        dialog = ctk.CTkToplevel(self)
        dialog.geometry("300x300")
        dialog.title("Yeni Kayıt")
        dialog.configure(fg_color=COLOR_BG)
        
        ctk.CTkLabel(dialog, text="Site Adı:", text_color=COLOR_FG).pack(pady=5)
        e_site = ctk.CTkEntry(dialog)
        e_site.pack(pady=5)
        
        ctk.CTkLabel(dialog, text="Kullanıcı Adı:", text_color=COLOR_FG).pack(pady=5)
        e_user = ctk.CTkEntry(dialog)
        e_user.pack(pady=5)
        
        ctk.CTkLabel(dialog, text="Şifre:", text_color=COLOR_FG).pack(pady=5)
        e_pass = ctk.CTkEntry(dialog)
        e_pass.pack(pady=5)
        
        def save():
            if e_site.get() and e_pass.get():
                self.logic.add_secret(e_site.get(), e_user.get(), e_pass.get())
                dialog.destroy()
                self.refresh_list()
                
        ctk.CTkButton(dialog, text="KAYDET", command=save, fg_color=COLOR_FG, text_color="black").pack(pady=20)

if __name__ == "__main__":
    app = App()
    app.mainloop()
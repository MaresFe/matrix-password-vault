import customtkinter as ctk
import os
import json
import base64
import hashlib
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- 1. AYARLAR VE RENKLER ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

COLOR_BG = "#050505"       # Daha derin siyah
COLOR_CARD = "#121212"     # Kartlar için koyu gri
COLOR_FG = "#00ff41"       # Matrix Yeşili
COLOR_BORDER = "#004d00"   # Kenarlıklar
FONT_MAIN = ("Courier New", 14, "bold")
FONT_HEADER = ("Courier New", 20, "bold")
DB_FILE = "matrix_vault.json"

# --- 2. DİL SÖZLÜĞÜ (TRANSLATIONS) ---
LANG = {
    "TR": {
        "title": "HACKER KASA v2.0",
        "setup_title": "[ SİSTEM KURULUMU ]",
        "login_title": "[ GÜVENLİ GİRİŞ ]",
        "ph_master": "Ana Şifre Belirle",
        "ph_login": "Ana Şifre",
        "btn_setup": "KURULUMU TAMAMLA",
        "btn_login": "KİLİDİ AÇ",
        "btn_add": "+ YENİ KAYIT",
        "btn_copy": "KOPYALA",
        "btn_save": "KAYDET",
        "list_header": "KAYITLI ŞİFRELER",
        "lbl_site": "Site Adı:",
        "lbl_user": "Kullanıcı Adı:",
        "lbl_pass": "Şifre:",
        "err_login": "[ERİŞİM REDDEDİLDİ]",
        "msg_copy": "Panoya Kopyalandı!",
        "lang_switch": "DİL: TR"
    },
    "EN": {
        "title": "HACKER VAULT v2.0",
        "setup_title": "[ SYSTEM SETUP ]",
        "login_title": "[ SECURE LOGIN ]",
        "ph_master": "Set Master Password",
        "ph_login": "Master Password",
        "btn_setup": "COMPLETE SETUP",
        "btn_login": "UNLOCK",
        "btn_add": "+ NEW ENTRY",
        "btn_copy": "COPY",
        "btn_save": "SAVE",
        "list_header": "STORED SECRETS",
        "lbl_site": "Site Name:",
        "lbl_user": "Username:",
        "lbl_pass": "Password:",
        "err_login": "[ACCESS DENIED]",
        "msg_copy": "Copied to Clipboard!",
        "lang_switch": "LANG: EN"
    }
}

# --- 3. BACKEND (Mantık - Değişmedi) ---
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
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
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

# --- 4. FRONTEND (Gelişmiş Arayüz) ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.logic = VaultLogic()
        self.current_lang = "TR"  # Varsayılan dil
        
        # Pencere Ayarları
        self.title("CipherVault")
        self.geometry("700x600")
        self.configure(fg_color=COLOR_BG)
        
        # Başlangıç Ekranı
        if self.logic.data["master_hash"] is None:
            self.show_register()
        else:
            self.show_login()

    # --- Yardımcı: Metin Çevirici ---
    def t(self, key):
        """O anki dile göre metni getirir"""
        return LANG[self.current_lang].get(key, key)

    def toggle_language(self):
        """Dili değiştirir ve ekranı yeniler"""
        self.current_lang = "EN" if self.current_lang == "TR" else "TR"
        # Hangi ekrandaysak onu yeniden çizmeliyiz
        # Basitlik için: Login'de değilsek Dashboard'u, Login'deysek Login'i yenile
        # Ancak burada dinamik yenileme için basit bir yol izleyeceğiz:
        if hasattr(self, 'dashboard_active') and self.dashboard_active:
            self.show_dashboard()
        elif self.logic.data["master_hash"] is None:
            self.show_register()
        else:
            self.show_login()

    def clear_screen(self):
        self.dashboard_active = False
        for widget in self.winfo_children():
            widget.destroy()

    # --- Header (Dil Butonu Burada) ---
    def add_header(self, parent_frame=None):
        target = parent_frame if parent_frame else self
        
        header_frame = ctk.CTkFrame(target, fg_color="transparent", height=40)
        header_frame.pack(fill="x", padx=20, pady=10)
        
        # Dil Butonu (Sağ Üst)
        btn_lang = ctk.CTkButton(header_frame, 
                                 text=self.t("lang_switch"), 
                                 command=self.toggle_language,
                                 width=80, height=25,
                                 fg_color="transparent", border_width=1, border_color=COLOR_FG,
                                 text_color=COLOR_FG, font=("Courier New", 12, "bold"))
        btn_lang.pack(side="right")

    # --- 1. EKRAN: KAYIT ---
    def show_register(self):
        self.clear_screen()
        self.add_header() # Dil butonunu ekle
        
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(expand=True)
        
        ctk.CTkLabel(frame, text=self.t("setup_title"), font=FONT_HEADER, text_color=COLOR_FG).pack(pady=30)
        
        self.entry_reg = ctk.CTkEntry(frame, placeholder_text=self.t("ph_master"), width=300, show="*",
                                      fg_color=COLOR_CARD, border_color=COLOR_FG, text_color="white")
        self.entry_reg.pack(pady=10)
        
        ctk.CTkButton(frame, text=self.t("btn_setup"), command=self.handle_register,
                      fg_color=COLOR_FG, text_color="black", hover_color="#00cc33").pack(pady=20)

    def handle_register(self):
        pwd = self.entry_reg.get()
        if pwd:
            self.logic.register(pwd)
            self.show_login()

    # --- 2. EKRAN: GİRİŞ ---
    def show_login(self):
        self.clear_screen()
        self.add_header()
        
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(expand=True)
        
        ctk.CTkLabel(frame, text=self.t("login_title"), font=FONT_HEADER, text_color=COLOR_FG).pack(pady=30)
        
        self.entry_login = ctk.CTkEntry(frame, placeholder_text=self.t("ph_login"), width=300, show="*",
                                        fg_color=COLOR_CARD, border_color=COLOR_FG, text_color="white")
        self.entry_login.pack(pady=10)
        
        self.lbl_error = ctk.CTkLabel(frame, text="", text_color="red", font=("Courier New", 12))
        self.lbl_error.pack(pady=5)

        ctk.CTkButton(frame, text=self.t("btn_login"), command=self.handle_login,
                      fg_color=COLOR_FG, text_color="black", hover_color="#00cc33").pack(pady=20)

    def handle_login(self):
        pwd = self.entry_login.get()
        if self.logic.login(pwd):
            self.show_dashboard()
        else:
            self.lbl_error.configure(text=self.t("err_login"))
            self.entry_login.configure(border_color="red")

    # --- 3. EKRAN: ANA PANEL (DASHBOARD) ---
    def show_dashboard(self):
        self.clear_screen()
        self.dashboard_active = True
        
        # Üst Panel
        top_frame = ctk.CTkFrame(self, fg_color="#0a0a0a", corner_radius=0)
        top_frame.pack(fill="x", pady=0)
        
        # Logo ve Dil Butonu
        title = ctk.CTkLabel(top_frame, text=self.t("title"), font=FONT_HEADER, text_color=COLOR_FG)
        title.pack(side="left", padx=20, pady=20)
        
        btn_lang = ctk.CTkButton(top_frame, text=self.t("lang_switch"), command=self.toggle_language,
                                 width=80, fg_color="#222", hover_color="#333", border_width=1, border_color="#444")
        btn_lang.pack(side="right", padx=20)

        # "Yeni Ekle" Butonu (Büyük ve Belirgin)
        btn_add = ctk.CTkButton(self, text=self.t("btn_add"), command=self.popup_add,
                                fg_color=COLOR_BORDER, hover_color=COLOR_FG, text_color="white", height=40)
        btn_add.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(self, text=self.t("list_header"), text_color="#666", font=("Arial", 12)).pack(anchor="w", padx=25)

        # Kaydırılabilir Alan
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.refresh_list()

    def refresh_list(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
            
        for site, info in self.logic.data["secrets"].items():
            # KART TASARIMI
            card = ctk.CTkFrame(self.scroll_frame, fg_color=COLOR_CARD, border_width=1, border_color="#333")
            card.pack(fill="x", pady=5, padx=5)
            
            # Sol taraf: Bilgiler
            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.pack(side="left", padx=10, pady=10)
            
            ctk.CTkLabel(info_frame, text=site, font=("Courier New", 16, "bold"), text_color="white").pack(anchor="w")
            ctk.CTkLabel(info_frame, text=info['username'], font=("Courier New", 12), text_color="#888").pack(anchor="w")
            
            # Sağ taraf: Buton
            ctk.CTkButton(card, text=self.t("btn_copy"), width=80,
                          command=lambda p=info['password']: self.copy_pass(p),
                          fg_color="transparent", border_width=1, border_color=COLOR_FG, 
                          text_color=COLOR_FG, hover_color="#111").pack(side="right", padx=15)

    def copy_pass(self, encrypted_pass):
        decrypted = self.logic.decrypt_password(encrypted_pass)
        pyperclip.copy(decrypted)
        # Kullanıcıya ufak bir geri bildirim (Notification)
        top = ctk.CTkToplevel(self)
        top.geometry("200x50")
        top.title("")
        # Pencereyi ekranın ortasına getirme
        x = self.winfo_x() + (self.winfo_width() // 2) - 100
        y = self.winfo_y() + (self.winfo_height() // 2)
        top.geometry(f"+{x}+{y}")
        top.overrideredirect(True) # Pencere kenarlıklarını kaldır
        lbl = ctk.CTkLabel(top, text=self.t("msg_copy"), fg_color=COLOR_FG, text_color="black", corner_radius=10)
        lbl.pack(fill="both", expand=True)
        top.after(1000, top.destroy) # 1 saniye sonra kapat

    def popup_add(self):
        dialog = ctk.CTkToplevel(self)
        dialog.geometry("350x350")
        dialog.title(self.t("btn_add"))
        dialog.configure(fg_color=COLOR_BG)
        dialog.attributes("-topmost", True)
        
        def entry_field(lbl_text):
            ctk.CTkLabel(dialog, text=lbl_text, text_color=COLOR_FG).pack(pady=(10, 0))
            e = ctk.CTkEntry(dialog, fg_color=COLOR_CARD, border_color="#333", text_color="white")
            e.pack(pady=5)
            return e
            
        e_site = entry_field(self.t("lbl_site"))
        e_user = entry_field(self.t("lbl_user"))
        e_pass = entry_field(self.t("lbl_pass"))
        
        def save():
            if e_site.get() and e_pass.get():
                self.logic.add_secret(e_site.get(), e_user.get(), e_pass.get())
                dialog.destroy()
                self.refresh_list()
                
        ctk.CTkButton(dialog, text=self.t("btn_save"), command=save, fg_color=COLOR_FG, text_color="black").pack(pady=25)

if __name__ == "__main__":
    app = App()
    app.mainloop()
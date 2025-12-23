import os
import json
import base64
import hashlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- RENK KODLARI (Hacker Teması) ---
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

DB_FILE = "my_vault.json"

class SimpleVault:
    def __init__(self):
        self.key = None # Şifreleme anahtarı (Giriş yapınca oluşacak)
        self.data = self.load_db()

    def load_db(self):
        """JSON dosyasını yükler, yoksa boş şablon oluşturur."""
        if not os.path.exists(DB_FILE):
            return {"salt": None, "master_hash": None, "secrets": {}}
        
        with open(DB_FILE, "r") as f:
            return json.load(f)

    def save_db(self):
        """Verileri dosyaya kaydeder."""
        with open(DB_FILE, "w") as f:
            json.dump(self.data, f, indent=4)

    def derive_key(self, password, salt):
        """
        Hash + Salt Mantığı Burasıdır!
        Şifreden hem doğrulama hash'i hem de şifreleme anahtarı üretir.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup(self):
        """İlk kurulum: Ana şifreyi belirle."""
        print(f"{GREEN}[+] Kasa bulunamadı. Yeni kurulum yapılıyor...{RESET}")
        password = getpass.getpass(f"{BOLD}Yeni Ana Şifreniz: {RESET}")
        confirm = getpass.getpass(f"{BOLD}Tekrar Girin: {RESET}")

        if password != confirm:
            print(f"{RED}[!] Şifreler uyuşmuyor!{RESET}")
            return False

        # 1. Salt oluştur (Rastgele tuz)
        salt = os.urandom(16)
        
        # 2. Anahtarı türet
        self.key = self.derive_key(password, salt)
        
        # 3. Veritabanına hash ve salt'ı kaydet (Şifrenin kendisini ASLA kaydetmeyiz!)
        # Hash'i saklamak için SHA256 özetini alıyoruz
        master_hash = hashlib.sha256(password.encode()).hexdigest()

        self.data["salt"] = base64.b64encode(salt).decode('utf-8')
        self.data["master_hash"] = master_hash
        self.save_db()
        
        print(f"{GREEN}[OK] Kurulum tamamlandı! Giriş yapabilirsiniz.{RESET}")
        return True

    def login(self):
        """Giriş yapma ve Anahtar Türetme"""
        if self.data["master_hash"] is None:
            return self.setup()

        print(f"{GREEN}=== GÜVENLİ KASA GİRİŞİ ==={RESET}")
        password = getpass.getpass(f"{BOLD}Ana Şifre: {RESET}")

        # Kayıtlı Salt'ı geri al
        salt = base64.b64decode(self.data["salt"])
        
        # Girilen şifrenin Hash'ini kontrol et
        check_hash = hashlib.sha256(password.encode()).hexdigest()

        if check_hash == self.data["master_hash"]:
            # Şifre doğruysa, şifreleme anahtarını (Key) türet
            self.key = self.derive_key(password, salt)
            print(f"{GREEN}[OK] Giriş Başarılı!{RESET}")
            return True
        else:
            print(f"{RED}[X] Hatalı Şifre!{RESET}")
            return False

    def add_password(self):
        site = input("Site/Uygulama Adı: ")
        username = input("Kullanıcı Adı: ")
        password = input("Şifre: ")

        # Veriyi Şifrele (Encryption)
        f = Fernet(self.key)
        encrypted_pwd = f.encrypt(password.encode()).decode()

        self.data["secrets"][site] = {
            "username": username,
            "password": encrypted_pwd  # Şifreli hali saklanır
        }
        self.save_db()
        print(f"{GREEN}[+] {site} için şifre güvenle saklandı!{RESET}")

    def show_passwords(self):
        if not self.data["secrets"]:
            print("Henüz kayıtlı şifre yok.")
            return

        print(f"\n{BOLD}{'SITE':<20} | {'KULLANICI':<20} | {'ŞİFRE'}{RESET}")
        print("-" * 60)
        
        f = Fernet(self.key)

        for site, info in self.data["secrets"].items():
            encrypted_pwd = info["password"]
            # Şifreyi Çöz (Decryption)
            try:
                decrypted_pwd = f.decrypt(encrypted_pwd.encode()).decode()
                print(f"{site:<20} | {info['username']:<20} | {GREEN}{decrypted_pwd}{RESET}")
            except:
                print(f"{site:<20} | {info['username']:<20} | {RED}Çözülemedi!{RESET}")
        print("-" * 60 + "\n")

# --- ANA PROGRAM DÖNGÜSÜ ---
if __name__ == "__main__":
    vault = SimpleVault()
    
    if vault.login():
        while True:
            print(f"\n{BOLD}1.{RESET} Şifre Ekle  {BOLD}2.{RESET} Şifreleri Gör  {BOLD}q.{RESET} Çıkış")
            choice = input("Seçiminiz: ")

            if choice == "1":
                vault.add_password()
            elif choice == "2":
                vault.show_passwords()
            elif choice == "q":
                print("Kasa kilitleniyor...")
                break
            else:
                print("Geçersiz seçim.")
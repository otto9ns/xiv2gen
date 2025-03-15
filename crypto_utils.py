from cryptography.fernet import Fernet
import cryptography.fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import base64, secrets, string, cryptography

def generate_password(password_length):
      alphabet = string.ascii_letters + string.digits
      return ''.join(secrets.choice(alphabet) for i in range(password_length))

def generate_salt(): # Генерация случайной соли
      return secrets.token_bytes(32)

def load_salt(): # Загрузка существующей соли из одноименного файла
      return open("data/salt", "rb").read()

def derive_key(salt, password): # Создание ключа на основе пароля и соли
      kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
      return kdf.derive(password.encode())

def generate_encryption_key(password, load_existing_salt=False, save_salt=True): 
      if load_existing_salt:
            salt = load_salt()
      elif save_salt:
            salt = generate_salt()

            with open("data/salt", "wb") as file:
                  file.write(salt)

      derived_key = derive_key(salt, password)
      return base64.urlsafe_b64encode(derived_key)

def encrypt(totp_key_unencrypted, encryption_key):
      cipher = Fernet(encryption_key)
      totp_key_encrypted = cipher.encrypt(totp_key_unencrypted.encode())

      with open("data/TOTP.key", "wb") as file:
            file.write(totp_key_encrypted)

def decrypt(encryption_key):
      cipher = Fernet(encryption_key)

      try: 
            with open("data/TOTP.key", "rb") as file:
                  totp_key_encrypted = file.read()

            return cipher.decrypt(totp_key_encrypted).decode()
      
      except cryptography.fernet.InvalidToken:
            print("Ошибка расшифровки: введен неверный пароль.")
      except FileNotFoundError:
            print("Файл TOTP.key не найден или не может быть прочитан.")
      except Exception as e:
            print(f"Неизвестная ошибка: {str(e)}")

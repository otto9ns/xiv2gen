import pyotp, requests, os, base64, argparse
from crypto_utils import *

def setup(password):

      while True:
            totp_key_unencrypted = input("Введите ваш TOTP: ")

            try:
                  if not totp_key_unencrypted:
                        raise ValueError
                  
                  base64.b32decode(totp_key_unencrypted, casefold=True)
                  pyotp.TOTP(totp_key_unencrypted)

                  break

            except (ValueError, TypeError):
                  print("Введенный вами TOTP имеет неверный формат.")

      os.makedirs("data") # Создать папку data
      
      encryption_key = generate_encryption_key(password=password)
      encrypt(totp_key_unencrypted, encryption_key)

parser = argparse.ArgumentParser()

parser.add_argument("--save-password", action="store_true", help="Сохраняется пароль в отдельном файле в директории data (НЕБЕЗОПАСНО!!!)")
parser.add_argument("--generate-password", action="store_true", help="Автоматически создает безопасный пароль")
parser.add_argument("--password-length", type=int, help="Задает размер автоматически генерируемого пароля")
parser.add_argument("-d", "--dry-run", action="store_true", help="Запускает xiv2gen в холостом режиме - ключи будут сгенерированы, однако попытки подключиться к xivlauncher произведено не будет")

parser._option_string_actions["-h"].help = "Показывает это сообщение и завершает работу xiv2gen"

args = parser.parse_args()

if args.password_length and not args.generate_password:
      parser.error("--password-length требует явного использования --generate-password")

if args.generate_password and (os.path.exists("data/TOTP.key") and os.path.isfile("data/TOTP.key")):
      parser.error("--generate-password !!! TOTP.key уже сгенерирован с использованием другого пароля")

if args.generate_password:
      password_length = args.password_length if args.password_length else 20
      password = generate_password(password_length)

      print(f"Ваша пасс-фраза: {password}")
else:
      if os.path.exists("data/password.txt") and os.path.isfile("data/password.txt"):
            with open("data/password.txt", "r") as file:
                  password = file.read()
      
      else:
            password = input("Введите вашу пасс-фразу: ")

if not os.path.exists("data/TOTP.key") or not os.path.isfile("data/TOTP.key"):
      setup(password)

if args.save_password:
      with open("data/password.txt", "w") as file:
            file.write(password)

totp_key_unencrypted = decrypt(generate_encryption_key(password=password, load_existing_salt=True, save_salt=False))

if totp_key_unencrypted and not args.dry_run:
      
      totp = pyotp.TOTP(totp_key_unencrypted)
      url = f"http://127.0.0.1:4646/ffxivlauncher/{totp.now()}"

      try:
            responce = requests.get(url)
            responce.raise_for_status()

      except requests.exceptions.RequestException as error:
            print(f"Не удалось подключиться к xivlauncher. \nОшибка: {error}")

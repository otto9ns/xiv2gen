# xiv2gen

## Предостережение

Использование xiv2gen на корню рушит концепцию двухэтапной аутентификации, которая изначально предполагает, что одноразовые коды будут генерироваться на другом устройстве, вы же собираетесь генерировать их на том же устройстве, на котором запускается xivlauncher. Прошу вас, держите в голове тот факт, что используя xiv2gen вы добровольно жертвуете собственной безопасностью ради мнимого удобства использования. 

Более безопасный вариант от команды xivlauncher: https://goatcorp.github.io/faq/mobile_otp.html

## Поддерживаемые аргументы

```
### otto@archlinux $ python main.py --help

usage: main.py [-h] [--save-password] [--generate-password] [--password-length PASSWORD_LENGTH] [-d]

options:
  -h, --help            Показать это сообщение и завершить работу xiv2gen
  --save-password       Сохраняется пароль в отдельном файле в директории data (НЕБЕЗОПАСНО!!!)
  --generate-password   Автоматически создает безопасный пароль
  --password-length PASSWORD_LENGTH
                        Задает размер автоматически генерируемого пароля
  -d, --dry-run         Запускает xiv2gen в холостом режиме - ключи будут сгенерированы, однако попытки подключиться к xivlauncher произведено не будет
```

## Установка xiv2gen

1. Создайте виртуальное оружение venv, запустив команду ```python -m venv .venv```, находясь в директории xiv2gen. 
2. Активируйте новосозданное виртуальное окружение, запустив скрипт ```.venv/Scripts/activate.ps1``` *(Windows)* или ```.venv/bin/activate``` *(MacOS/Linux)*. 
3. Установите все необходимые для работы xiv2gen зависимости командой ```pip install -r requirements.txt```. 
4. Запустите xiv2gen, обратившись к нему из командной строки или терминала следующим образом: ```python main.py```. Обратите внимание на [справку по поддерживаемым аргументам](#поддерживаемые-аргументы).

Для того, чтобы xiv2gen смог подключиться к вашему xivlauncher, пожалуйста, поставьте галочку как показано на прикрепленной ниже картинке. </br>
![image](https://goatcorp.github.io/faq/asset/otp_checkbox.png)  

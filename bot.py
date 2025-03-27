import sys
import os
import telebot
from telebot import types
from dotenv import load_dotenv

# Настройка пути к папке src
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
print(f"Путь к src: {src_path}")
if not os.path.exists(src_path):
    print("Ошибка: папка src не найдена!")
    sys.exit(1)
sys.path.insert(0, src_path)

# Импорт всех модулей из src (с учетом названий папок из скриншота)
try:
    from clickjacking.clickjacking import ClickJacking
    from dnslookup.dnslookup import DnsLookup
    from http_headers_grabber.http_headers_grabber import HttpHeadersGrabber
    from ip.ip import Ip
    from ip_info_finder.ip_info_finder import IpInfoFinder
    from logger.logger import Logger
    from nmap_scanner.nmap_scanner import NmapScanner
    from one_sec_mail.one_sec_mail import OneSecMail
    from phone_info.phone_info import PhoneInfo
    from pwned.pwned import PasswordPwned
    from robots_scanner.robots_scanner import RobotsScanner
    from whois_lookup.whois_lookup import WhoisLookup
except ModuleNotFoundError as e:
    print(f"Ошибка импорта: {e}")
    sys.exit(1)

# Загрузка токена из .env
load_dotenv()
API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN:
    print("Ошибка: API_TOKEN не найден в .env")
    sys.exit(1)

# Инициализация бота и логгера
bot = telebot.TeleBot(API_TOKEN)
logger = Logger("GodsEyeBot", "bot.log")

# Функция для отправки длинных сообщений
def send_long_message(chat_id, text):
    for i in range(0, len(text), 4096):
        bot.send_message(chat_id, text[i:i + 4096])

# Обработчик команды /start
@bot.message_handler(commands=['start'])
def handle_start(message):
    welcome_text = (
        "Добро пожаловать в Gods-eye Bot! 👁️\n"
        "Я помогу вам собрать информацию. Используйте команды:\n"
        "/phoneinfo <номер> — Информация о номере телефона (например, /phoneinfo +12025550123)\n"
        "/dnslookup <домен> — DNS-информация (например, /dnslookup google.com)\n"
        "/clickjacking <домен> — Проверка уязвимости к кликджекингу (например, /clickjacking example.com)\n"
        "/httpheaders <домен> — Получить HTTP-заголовки (например, /httpheaders google.com)\n"
        "/getip <домен> — Получить IP домена (например, /getip google.com)\n"
        "/ipinfo <ip> — Информация об IP (например, /ipinfo 8.8.8.8)\n"
        "/nmap <цель> — Сканирование с помощью Nmap (например, /nmap 192.168.1.1)\n"
        "/genemail — Сгенерировать временный email\n"
        "/pwned <пароль> — Проверить пароль на утечки (например, /pwned mypassword)\n"
        "/robots <домен> — Сканировать robots.txt (например, /robots google.com)\n"
        "/whois <домен> — WHOIS-информация (например, /whois google.com)"
    )
    bot.send_message(message.chat.id, welcome_text)
    logger.info(f"Пользователь {message.from_user.id} запустил бота")

# Обработчик команды /phoneinfo
@bot.message_handler(commands=['phoneinfo'])
def handle_phoneinfo(message):
    try:
        phone_number = message.text.split(' ', 1)[1]
        phone_info = PhoneInfo(phone_number)
        country = phone_info.get_country()
        operator = phone_info.get_operator()
        response = f"Информация о номере {phone_number}:\nСтрана: {country}\nОператор: {operator}"
        bot.send_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил информацию о номере {phone_number}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите номер телефона в формате: /phoneinfo +12025550123")
        logger.error(f"Пользователь {message.from_user.id} не указал номер телефона")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при запросе информации о номере: {str(e)}")

# Обработчик команды /dnslookup
@bot.message_handler(commands=['dnslookup'])
def handle_dnslookup(message):
    try:
        domain = message.text.split(' ', 1)[1]
        dns_lookup = DnsLookup(domain)
        dns_info = dns_lookup.get_info()
        response = f"DNS информация для {domain}:\n{dns_info}"
        send_long_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил DNS-информацию для {domain}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите домен в формате: /dnslookup google.com")
        logger.error(f"Пользователь {message.from_user.id} не указал домен для DNS-запроса")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при DNS-запросе: {str(e)}")

# Обработчик команды /clickjacking
@bot.message_handler(commands=['clickjacking'])
def handle_clickjacking(message):
    try:
        domain = message.text.split(' ', 1)[1]
        clickjacking = ClickJacking(domain)
        is_vulnerable = clickjacking.is_vulnerable()
        if is_vulnerable:
            bot.send_message(message.chat.id, f"Внимание! Домен {domain} уязвим к Clickjacking!")
        else:
            bot.send_message(message.chat.id, f"Домен {domain} не уязвим к Clickjacking.")
        logger.info(f"Пользователь {message.from_user.id} проверил уязвимость {domain} к кликджекингу")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите домен в формате: /clickjacking example.com")
        logger.error(f"Пользователь {message.from_user.id} не указал домен для проверки кликджекинга")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при проверке кликджекинга: {str(e)}")

# Обработчик команды /httpheaders
@bot.message_handler(commands=['httpheaders'])
def handle_httpheaders(message):
    try:
        domain = message.text.split(' ', 1)[1]
        headers_grabber = HttpHeadersGrabber(domain)
        headers = headers_grabber.get_headers()
        response = f"HTTP-заголовки для {domain}:\n"
        for key, value in headers.items():
            response += f"{key}: {value}\n"
        send_long_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил HTTP-заголовки для {domain}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите домен в формате: /httpheaders google.com")
        logger.error(f"Пользователь {message.from_user.id} не указал домен для получения HTTP-заголовков")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при получении HTTP-заголовков: {str(e)}")

# Обработчик команды /getip
@bot.message_handler(commands=['getip'])
def handle_getip(message):
    try:
        domain = message.text.split(' ', 1)[1]
        ip = Ip(domain)
        ip_address = ip.get_ip()
        response = f"IP-адрес домена {domain}:\n{ip_address}"
        bot.send_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил IP для {domain}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите домен в формате: /getip google.com")
        logger.error(f"Пользователь {message.from_user.id} не указал домен для получения IP")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при получении IP: {str(e)}")

# Обработчик команды /ipinfo
@bot.message_handler(commands=['ipinfo'])
def handle_ipinfo(message):
    try:
        ip = message.text.split(' ', 1)[1]
        ip_info = IpInfoFinder(ip)
        info = ip_info.get_info()
        response = f"Информация об IP {ip}:\n"
        for key, value in info.items():
            response += f"{key}: {value}\n"
        send_long_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил информацию об IP {ip}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите IP в формате: /ipinfo 8.8.8.8")
        logger.error(f"Пользователь {message.from_user.id} не указал IP")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при запросе информации об IP: {str(e)}")

# Обработчик команды /nmap
@bot.message_handler(commands=['nmap'])
def handle_nmap(message):
    try:
        target = message.text.split(' ', 1)[1]
        nmap = NmapScanner(target)
        result = nmap.scan()
        response = f"Результат сканирования Nmap для {target}:\n{result}"
        send_long_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} выполнил Nmap-сканирование для {target}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите цель в формате: /nmap 192.168.1.1")
        logger.error(f"Пользователь {message.from_user.id} не указал цель для Nmap-сканирования")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при Nmap-сканировании: {str(e)}")

# Обработчик команды /genemail
@bot.message_handler(commands=['genemail'])
def handle_genemail(message):
    try:
        email_generator = OneSecMail()
        email = email_generator.generate_email()
        response = f"Сгенерированный временный email:\n{email[0] if isinstance(email, list) else email}"
        bot.send_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} сгенерировал временный email")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при генерации email: {str(e)}")

# Обработчик команды /pwned
@bot.message_handler(commands=['pwned'])
def handle_pwned(message):
    try:
        password = message.text.split(' ', 1)[1]
        pwned = PasswordPwned(password)
        count = pwned.is_pwned()
        if count > 0:
            response = f"Пароль '{password}' был скомпрометирован {count} раз!"
        elif count == 0:
            response = f"Пароль '{password}' не найден в утечках."
        else:
            response = "Не удалось проверить пароль."
        bot.send_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} проверил пароль")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите пароль в формате: /pwned mypassword")
        logger.error(f"Пользователь {message.from_user.id} не указал пароль")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при проверке пароля: {str(e)}")

# Обработчик команды /robots
@bot.message_handler(commands=['robots'])
def handle_robots(message):
    try:
        domain = message.text.split(' ', 1)[1]
        robots = RobotsScanner(domain)
        result = robots.scan()
        response = f"Содержимое robots.txt для {domain}:\n{result}"
        send_long_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил robots.txt для {domain}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите домен в формате: /robots google.com")
        logger.error(f"Пользователь {message.from_user.id} не указал домен для сканирования robots.txt")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при сканировании robots.txt: {str(e)}")

# Обработчик команды /whois
@bot.message_handler(commands=['whois'])
def handle_whois(message):
    try:
        domain = message.text.split(' ', 1)[1]
        whois = WhoisLookup(domain)
        result = whois.get_info()
        response = f"WHOIS-информация для {domain}:\n{result}"
        send_long_message(message.chat.id, response)
        logger.info(f"Пользователь {message.from_user.id} запросил WHOIS-информацию для {domain}")
    except IndexError:
        bot.send_message(message.chat.id, "Пожалуйста, введите домен в формате: /whois google.com")
        logger.error(f"Пользователь {message.from_user.id} не указал домен для WHOIS-запроса")
    except Exception as e:
        bot.send_message(message.chat.id, f"Ошибка: {str(e)}")
        logger.error(f"Ошибка при WHOIS-запросе: {str(e)}")

# Запуск бота
if __name__ == "__main__":
    print("Бот запущен...")
    logger.info("Бот запущен")
    try:
        bot.polling(non_stop=True)
    except Exception as e:
        print(f"Ошибка при запуске бота: {e}")
        logger.error(f"Ошибка при запуске бота: {str(e)}")
        sys.exit(1)
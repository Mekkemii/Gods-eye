import sys
import os
import logging
from dotenv import load_dotenv
from telegram.ext import Updater, CommandHandler, MessageHandler, filters

# Настройка пути к папке src
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
print(f"Путь к src: {src_path}")
if not os.path.exists(src_path):
    print("Ошибка: папка src не найдена!")
    sys.exit(1)
sys.path.insert(0, src_path)

# Импорт всех модулей из src
try:
    from click_jacking.click_jacking import ClickJacking
    from dns_lookup.dns_lookup import DnsLookup
    from http_headers_grabber.http_headers_grabber import HttpHeadersGrabber
    from ip.ip_class import GetHostname  # Исправленный импорт после переименования
    from ip_info_finder.ip_info_finder import IpInfoFinder
    from logger.logger import Logger
    from nmap_scanner.nmap_scanner import NmapScanner
    from one_sec_mail.one_sec_mail import OneSecMail
    from phone_info.phone_info import PhoneInfo
    from pwned.pwned import PasswordPwned
    from robots_scanner.robots_scanner import RobotsScanner
    from whois_lookup.whois_lookup import WhoisLookup
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    sys.exit(1)

# Загрузка токена из .env
load_dotenv()
API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN:
    print("Ошибка: API_TOKEN не найден в .env")
    sys.exit(1)

# Настройка логирования
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Функция для отправки длинных сообщений
def send_long_message(update, text):
    for i in range(0, len(text), 4096):
        update.message.reply_text(text[i:i + 4096])

# Обработчик команды /start
def handle_start(update, context):
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
    update.message.reply_text(welcome_text)
    logger.info(f"Пользователь {update.message.from_user.id} запустил бота")

# Обработчик команды /phoneinfo
def handle_phoneinfo(update, context):
    try:
        phone_number = context.args[0]
        phone_info = PhoneInfo(phone_number)
        country = phone_info.get_country()
        operator = phone_info.get_operator()
        response = f"Информация о номере {phone_number}:\nСтрана: {country}\nОператор: {operator}"
        update.message.reply_text(response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил информацию о номере {phone_number}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите номер телефона: /phoneinfo +12025550123")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /dnslookup
def handle_dnslookup(update, context):
    try:
        domain = context.args[0]
        dns_lookup = DnsLookup(domain)
        dns_info = dns_lookup.get_info()
        response = f"DNS информация для {domain}:\n{dns_info}"
        send_long_message(update, response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил DNS для {domain}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите домен: /dnslookup google.com")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /clickjacking
def handle_clickjacking(update, context):
    try:
        domain = context.args[0]
        clickjacking = ClickJacking(domain)
        is_vulnerable = clickjacking.is_vulnerable()
        response = f"Домен {domain} уязвим к кликджекингу!" if is_vulnerable else f"Домен {domain} не уязвим."
        update.message.reply_text(response)
        logger.info(f"Пользователь {update.message.from_user.id} проверил {domain} на кликджекинг")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите домен: /clickjacking example.com")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /httpheaders
def handle_httpheaders(update, context):
    try:
        domain = context.args[0]
        headers_grabber = HttpHeadersGrabber(domain)
        headers = headers_grabber.get_headers()
        response = f"HTTP-заголовки для {domain}:\n{headers}"
        send_long_message(update, response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил заголовки для {domain}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите домен: /httpheaders google.com")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /getip
def handle_getip(update, context):
    try:
        hostname_ip = GetHostname()
        hostname = hostname_ip.get_hostname()
        ip_address = hostname_ip.get_ip()
        response = f"Hostname: {hostname}\nЛокальный IP: {ip_address}"
        update.message.reply_text(response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил hostname и IP")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /ipinfo
def handle_ipinfo(update, context):
    try:
        ip = context.args[0]
        ip_info = IpInfoFinder(ip)
        info = ip_info.get_info()
        response = f"Информация об IP {ip}:\n{info}"
        send_long_message(update, response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил информацию об IP {ip}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите IP: /ipinfo 8.8.8.8")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /nmap
def handle_nmap(update, context):
    try:
        target = context.args[0]
        nmap = NmapScanner(target)
        result = nmap.scan()
        response = f"Результат Nmap для {target}:\n{result}"
        send_long_message(update, response)
        logger.info(f"Пользователь {update.message.from_user.id} выполнил Nmap для {target}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите цель: /nmap 192.168.1.1")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /genemail
def handle_genemail(update, context):
    try:
        email_generator = OneSecMail()
        email = email_generator.generate_email()
        response = f"Временный email:\n{email}"
        update.message.reply_text(response)
        logger.info(f"Пользователь {update.message.from_user.id} сгенерировал email")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /pwned
def handle_pwned(update, context):
    try:
        password = context.args[0]
        pwned = PasswordPwned(password)
        count = pwned.is_pwned()
        response = f"Пароль '{password}' скомпрометирован {count} раз!" if count > 0 else f"Пароль '{password}' не найден в утечках."
        update.message.reply_text(response)
        logger.info(f"Пользователь {update.message.from_user.id} проверил пароль")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите пароль: /pwned mypassword")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /robots
def handle_robots(update, context):
    try:
        domain = context.args[0]
        robots = RobotsScanner(domain)
        result = robots.scan()
        response = f"robots.txt для {domain}:\n{result}"
        send_long_message(update, response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил robots.txt для {domain}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите домен: /robots google.com")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик команды /whois
def handle_whois(update, context):
    try:
        domain = context.args[0]
        whois = WhoisLookup(domain)
        result = whois.get_info()
        response = f"WHOIS для {domain}:\n{result}"
        send_long_message(update, response)
        logger.info(f"Пользователь {update.message.from_user.id} запросил WHOIS для {domain}")
    except IndexError:
        update.message.reply_text("Пожалуйста, введите домен: /whois google.com")
    except Exception as e:
        update.message.reply_text(f"Ошибка: {str(e)}")

# Обработчик неизвестных команд
def handle_unknown(update, context):
    update.message.reply_text("Неизвестная команда. Используйте /start для списка команд.")

# Обработчик ошибок
def error_handler(update, context):
    logger.error(f"Ошибка: {context.error}")
    update.message.reply_text("Произошла ошибка. Попробуйте позже.")

def main():
    updater = Updater(API_TOKEN)
    dp = updater.dispatcher

    # Добавление обработчиков
    dp.add_handler(CommandHandler("start", handle_start))
    dp.add_handler(CommandHandler("phoneinfo", handle_phoneinfo))
    dp.add_handler(CommandHandler("dnslookup", handle_dnslookup))
    dp.add_handler(CommandHandler("clickjacking", handle_clickjacking))
    dp.add_handler(CommandHandler("httpheaders", handle_httpheaders))
    dp.add_handler(CommandHandler("getip", handle_getip))
    dp.add_handler(CommandHandler("ipinfo", handle_ipinfo))
    dp.add_handler(CommandHandler("nmap", handle_nmap))
    dp.add_handler(CommandHandler("genemail", handle_genemail))
    dp.add_handler(CommandHandler("pwned", handle_pwned))
    dp.add_handler(CommandHandler("robots", handle_robots))
    dp.add_handler(CommandHandler("whois", handle_whois))
    dp.add_handler(MessageHandler(Filters.command, handle_unknown))
    dp.add_error_handler(error_handler)

    # Запуск бота
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
import requests
import socket
import ssl
import dns.resolver
import whois
from urllib.parse import urlparse
from datetime import datetime
import smtplib
import paramiko
from bs4 import BeautifulSoup
import re
import ftplib
import imaplib
from websocket import create_connection
import os
import sys
import logging
import subprocess
from colorama import Fore, Style, init

# Inicjalizacja colorama
init(autoreset=True)

# Konfiguracja logów
logging.basicConfig(filename='network_analysis_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ASCII Banner
BANNER = f"""
{Fore.RED}  _____   _____   _____   _____   _____   _____  
{Fore.YELLOW} /     \\ /     \\ /     \\ /     \\ /     \\ /     \\ 
{Fore.GREEN}|  O O  |  O O  |  O O  |  O O  |  O O  |  O O  |
{Fore.BLUE} \\_____//\\_____//\\_____//\\_____//\\_____//\\_____// 
{Fore.MAGENTA}Network Analysis Tool v3.0
{Fore.WHITE}By @ArsagrdKronos 
"""

# Funkcja wywołująca GCH.sss (dogłębna analiza WebSocket)
def run_gch_sss(host):
    logging.info(f"Wywoływanie GCH.sss dla {host}")
    try:
        result = subprocess.run(['bash', 'src/gch.sss', host], capture_output=True, text=True, timeout=30)
        print(f"{Fore.CYAN}Wynik GCH.sss (dogłębna analiza WebSocket):\n{result.stdout}")
        if result.stderr:
            print(f"{Fore.RED}Błędy GCH.sss:\n{result.stderr}")
        logging.info(f"GCH.sss output: {result.stdout}")
        return result.returncode
    except Exception as e:
        print(f"{Fore.RED}Błąd GCH.sss: {e} (Upewnij się, że src/gch.sss istnieje i ma prawa wykonania)")
        logging.error(f"Błąd GCH.sss: {e}")
        return 1

# Funkcja wywołująca RecordWebSkocet.rs (analiza lokalizacji IP)
def run_recordwebskocet_rs(host):
    logging.info(f"Wywoływanie RecordWebSkocet.rs dla {host}")
    try:
        # Kompilacja pliku Rust
        subprocess.run(['rustc', 'src/recordwebskocet.rs', '-o', 'src/recordwebskocet'], check=True)
        # Uruchomienie skompilowanego programu
        result = subprocess.run(['./src/recordwebskocet', host], capture_output=True, text=True, timeout=30)
        print(f"{Fore.CYAN}Wynik RecordWebSkocet.rs (lokalizacja IP):\n{result.stdout}")
        if result.stderr:
            print(f"{Fore.RED}Błędy RecordWebSkocet.rs:\n{result.stderr}")
        logging.info(f"RecordWebSkocet.rs output: {result.stdout}")
        return result.returncode
    except Exception as e:
        print(f"{Fore.RED}Błąd RecordWebSkocet.rs: {e} (Upewnij się, że Rust jest zainstalowany i src/recordwebskocet.rs istnieje)")
        logging.error(f"Błąd RecordWebSkocet.rs: {e}")
        return 1

def check_port(hostname, port, protocol_name, timeout=2):
    """Sprawdza, czy dany port jest otwarty."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        status = 'otwarty' if result == 0 else 'zamknięty'
        logging.info(f"{protocol_name}: Port {port} jest {status}")
        return result == 0, f"{protocol_name}: Port {port} jest {status}."
    except Exception as e:
        logging.error(f"{protocol_name}: Błąd - {e}")
        return False, f"{protocol_name}: Błąd - {e}"

def analyze_website(url=None, rhost=None, ehost=None):
    if rhost:
        hostname = rhost
        logging.info(f"Analiza zdalnego hosta: {rhost}")
        print(f"{Fore.YELLOW}Analiza zdalnego (publicznego) hosta: {rhost}")
    elif ehost:
        hostname = ehost
        logging.info(f"Analiza lokalnego hosta: {ehost}")
        print(f"{Fore.YELLOW}Analiza lokalnego hosta: {ehost}")
    else:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        logging.info(f"Analiza strony: {url}")
        print(f"{Fore.GREEN}\nAnaliza strony: {url}\n")

    # 1. Adres IP (IPv4/IPv6)
    try:
        ip_address = socket.getaddrinfo(hostname, None)
        ipv4 = list(set([x[4][0] for x in ip_address if x[0] == socket.AF_INET]))
        ipv6 = list(set([x[4][0] for x in ip_address if x[0] == socket.AF_INET6]))
        print(f"{Fore.CYAN}Adresy IP:")
        print(f"IPv4: {ipv4}")
        print(f"IPv6: {ipv6}")
        logging.info(f"IP dla {hostname}: IPv4={ipv4}, IPv6={ipv6}")
    except socket.gaierror:
        print(f"{Fore.RED}Błąd: Nie udało się uzyskać adresu IP.")
        logging.error(f"Błąd IP dla {hostname}")

    # 2. Analiza protokołów sieciowych
    protocols = [
        (80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (110, "POP3"), (995, "POP3S"),
        (25, "SMTP"), (465, "SMTPS"), (587, "SMTP (STARTTLS)"), (143, "IMAP"), (993, "IMAPS"),
        (21, "FTP"), (990, "FTPS"), (23, "Telnet"), (3389, "RDP"), (123, "NTP"), (161, "SNMP")
    ]
    print(f"{Fore.CYAN}\nAnaliza protokołów sieciowych:")
    for port, protocol in protocols:
        is_open, message = check_port(hostname, port, protocol)
        print(f"{Fore.GREEN if is_open else Fore.RED}{message}")

    # 3. Szczegółowa analiza SSL
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"{Fore.CYAN}\nSzczegółowe informacje o certyfikacie SSL:")
                print(f"Wystawca: {cert['issuer']}")
                print(f"Ważny od: {datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')}")
                print(f"Ważny do: {datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')}")
                print(f"Wersja SSL/TLS: {ssock.version()}")
                print(f"Algorytm podpisu: {cert.get('signatureAlgorithm', 'N/A')}")
                print(f"Alternatywne nazwy: {cert.get('subjectAltName', 'N/A')}")
                logging.info(f"SSL info dla {hostname}: {cert}")
    except Exception as e:
        print(f"{Fore.RED}Błąd SSL: {e}")
        logging.error(f"Błąd SSL dla {hostname}: {e}")

    # 4. Analiza SSH
    try:
        is_open, _ = check_port(hostname, 22, "SSH")
        if is_open:
            transport = paramiko.Transport((hostname, 22))
            transport.connect()
            banner = transport.get_banner()
            print(f"{Fore.CYAN}\nSSH Banner: {banner if banner else 'Brak banera'}")
            logging.info(f"SSH Banner dla {hostname}: {banner}")
            transport.close()
    except Exception as e:
        print(f"{Fore.RED}Błąd SSH: {e}")
        logging.error(f"Błąd SSH dla {hostname}: {e}")

    # 5. Analiza POP3S
    try:
        is_open, _ = check_port(hostname, 995, "POP3S")
        if is_open:
            with smtplib.SMTP_SSL(hostname, 995, context=ssl.create_default_context()) as server:
                print(f"{Fore.CYAN}\nPOP3S: Połączenie nawiązane, serwer aktywny.")
                logging.info(f"POP3S aktywny dla {hostname}")
    except Exception as e:
        print(f"{Fore.RED}Błąd POP3S: {e}")
        logging.error(f"Błąd POP3S dla {hostname}: {e}")

    # 6. Analiza IMAPS
    try:
        is_open, _ = check_port(hostname, 993, "IMAPS")
        if is_open:
            with imaplib.IMAP4_SSL(hostname, 993) as server:
                print(f"{Fore.CYAN}\nIMAPS: Połączenie nawiązane, serwer aktywny.")
                logging.info(f"IMAPS aktywny dla {hostname}")
    except Exception as e:
        print(f"{Fore.RED}Błąd IMAPS: {e}")
        logging.error(f"Błąd IMAPS dla {hostname}: {e}")

    # 7. Analiza FTPS
    try:
        is_open, _ = check_port(hostname, 990, "FTPS")
        if is_open:
            ftp = ftplib.FTP_TLS(hostname)
            ftp.login()  # Próba anonimowego logowania
            print(f"{Fore.CYAN}\nFTPS: Połączenie nawiązane, serwer aktywny.")
            logging.info(f"FTPS aktywny dla {hostname}")
            ftp.quit()
    except Exception as e:
        print(f"{Fore.RED}Błąd FTPS: {e}")
        logging.error(f"Błąd FTPS dla {hostname}: {e}")

    # 8. Analiza WebSocket (uzupełniona przez GCH.sss)
    try:
        ws_url = f"wss://{hostname}"
        ws = create_connection(ws_url, timeout=2)
        print(f"{Fore.CYAN}\nWebSocket: Połączenie aktywne.")
        logging.info(f"WebSocket aktywny dla {hostname}")
        ws.close()
    except Exception as e:
        print(f"{Fore.RED}WebSocket: Nieaktywny lub błąd - {e}")
        logging.error(f"Błąd WebSocket dla {hostname}: {e}")

    # 9. Rozszerzona analiza DNS
    print(f"{Fore.CYAN}\nRekordy DNS:")
    for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
        try:
            answers = dns.resolver.resolve(hostname, record_type)
            print(f"{record_type}:")
            for rdata in answers:
                print(f"  {rdata}")
            logging.info(f"DNS {record_type} dla {hostname}: {answers}")
        except dns.resolver.NoAnswer:
            print(f"{record_type}: Brak rekordu.")
            logging.info(f"DNS {record_type} dla {hostname}: Brak rekordu")
        except Exception as e:
            print(f"{record_type}: Błąd - {e}")
            logging.error(f"Błąd DNS {record_type} dla {hostname}: {e}")

    # 10. WHOIS
    try:
        w = whois.whois(hostname)
        print(f"{Fore.CYAN}\nInformacje WHOIS:")
        print(f"Domena: {w.domain_name}")
        print(f"Rejestrator: {w.registrar}")
        print(f"Data utworzenia: {w.creation_date}")
        print(f"Data wygaśnięcia: {w.expiration_date}")
        print(f"Serwery DNS: {w.name_servers}")
        logging.info(f"WHOIS dla {hostname}: {w}")
    except Exception as e:
        print(f"{Fore.RED}Błąd WHOIS: {e}")
        logging.error(f"Błąd WHOIS dla {hostname}: {e}")

    # 11. Nagłówki HTTP i Cookies
    if url:
        try:
            response = requests.get(url, timeout=5)
            print(f"{Fore.CYAN}\nNagłówki HTTP:")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
            logging.info(f"Nagłówki HTTP dla {url}: {response.headers}")
            print(f"{Fore.CYAN}\nCookies (pełne szczegóły):")
            if response.cookies:
                for cookie in response.cookies:
                    print(f"Nazwa: {cookie.name}")
                    print(f"Wartość: {cookie.value}")
                    print(f"Domena: {cookie.domain}")
                    print(f"Ścieżka: {cookie.path}")
                    print(f"Ważność: {cookie.expires}")
                    print(f"Bezpieczna: {cookie.secure}")
                    print("---")
                    logging.info(f"Cookie dla {url}: {cookie.name}, {cookie.value}")
            else:
                print("Brak cookies.")
                logging.info(f"Brak cookies dla {url}")
        except requests.RequestException as e:
            print(f"{Fore.RED}Błąd HTTP: {e}")
            logging.error(f"Błąd HTTP dla {url}: {e}")

    # 12. Analiza skryptów na stronie
    if url:
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script')
            print(f"{Fore.CYAN}\nSkrypty na stronie:")
            for i, script in enumerate(scripts, 1):
                src = script.get('src', 'Brak zewnętrznego źródła')
                print(f"Skrypt {i}: {src}")
                if script.string:
                    if re.search(r'alert\(|eval\(|document\.cookie', script.string, re.IGNORECASE):
                        print(f"{Fore.RED}  Ostrzeżenie: Możliwe niebezpieczne wyrażenia w skrypcie (np. alert, eval).")
                        logging.warning(f"Potencjalnie niebezpieczny skrypt w {url}: {src}")
            logging.info(f"Skrypty na stronie {url}: Znaleziono {len(scripts)} skryptów")
        except Exception as e:
            print(f"{Fore.RED}Błąd analizy skryptów: {e}")
            logging.error(f"Błąd analizy skryptów dla {url}: {e}")

    # Wywołanie skryptów z folderu src
    run_gch_sss(hostname)
    run_recordwebskocet_rs(hostname)

# Funkcja help
def show_help():
    help_text = f"""
{Fore.YELLOW}Dostępne komendy:
- analyze <url> : Analizuje podaną stronę (np. https://www.google.com).
- rhost <host> : Analizuje zdalny/publiczny host (np. google.com).
- ehost <host> : Analizuje lokalny host (np. localhost, 192.168.1.1).
- clear : Czyści terminal.
- help : Wyświetla tę pomoc.
- exit : Wyjście z programu.
"""
    print(help_text)
    logging.info("Wyświetlono pomoc")

# Główna pętla interaktywna
def main():
    print(BANNER)
    logging.info("Program uruchomiony")
    while True:
        command = input(f"{Fore.GREEN}>> {Style.RESET_ALL}").strip().lower()
        logging.info(f"Wykonano komendę: {command}")
        try:
            if command.startswith("analyze "):
                url = command.split(" ", 1)[1]
                analyze_website(url=url)
            elif command.startswith("rhost "):
                rhost = command.split(" ", 1)[1]
                analyze_website(rhost=rhost)
            elif command.startswith("ehost "):
                ehost = command.split(" ", 1)[1]
                analyze_website(ehost=ehost)
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                print(BANNER)
                logging.info("Wyczyszczono terminal")
            elif command == "help":
                show_help()
            elif command == "exit":
                logging.info("Program zakończony")
                print(f"{Fore.GREEN}Do zobaczenia!")
                sys.exit(0)
            else:
                print(f"{Fore.RED}Nieznana komenda. Użyj 'help' po listę.")
                logging.warning(f"Nieznana komenda: {command}")
        except Exception as e:
            print(f"{Fore.RED}Błąd: {e}")
            logging.error(f"Błąd podczas wykonywania komendy: {e}")

if __name__ == "__main__":
    main()
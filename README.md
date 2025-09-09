# 🌐 Network Analysis Tool v3.0

![Network Analysis Tool](https://img.shields.io/badge/version-3.0-blue.svg) ![Python](https://img.shields.io/badge/Python-3.8+-yellow.svg) ![Rust](https://img.shields.io/badge/Rust-1.65+-orange.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg)

Zaawansowane narzędzie do analizy sieciowej, które pozwala na dogłębne badanie stron internetowych, hostów zdalnych i lokalnych. Oferuje analizę protokołów sieciowych, certyfikatów SSL, WebSocket, geolokacji IP oraz wiele więcej, z interaktywnym interfejsem CLI i kolorowym outputem. 🛠️

## 🚀 Funkcjonalności

- **Analiza protokołów sieciowych**: HTTP, HTTPS, SSH, POP3, SMTP, IMAP, FTP, FTPS, Telnet, RDP, NTP, SNMP.
- **Dogłębna analiza WebSocket**: Szczegółowe informacje o połączeniu, wersji serwera i nagłówkach (`src/gch.sss`). 🌐
- **Geolokacja IP**: Analiza lokalizacji serwera (kraj, miasto, ISP, ASN, współrzędne) za pomocą `src/recordwebskocet.rs`. 📍
- **Interfejs CLI**: Komendy `analyze`, `rhost`, `ehost`, `clear`, `help`, `exit`.
- **Kolorowy output**: Używa `colorama` dla czytelnego wyświetlenia wyników. 🎨
- **Logowanie**: Wszystkie operacje zapisywane w `network_analysis_log.txt`. 📜
- **ASCII Banner**: Estetyczny baner startowy z listą twórców. ✨

## 📋 Wymagania

- **Python 3.8+** z bibliotekami:
  ```bash
  pip install requests python-whois dnspython paramiko beautifulsoup4 websocket-client colorama
  ```
- **Rust 1.65+** (dla `src/recordwebskocet.rs`):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  cargo add ipgeolocate reqwest tokio serde
  ```
- **Bash**: Dla `src/gch.sss` (wymaga `curl`).
- **System**: Linux/Windows/MacOS (testowane na Ubuntu 22.04 i Windows 10).

## 📂 Struktura projektu

```
project/
├── network_analyzer.py       # Główny skrypt Pythona
├── src/
│   ├── gch.sss              # Bash: analiza WebSocket
│   ├── recordwebskocet.rs   # Rust: geolokacja IP
├── network_analysis_log.txt  # Plik logów
├── README.md                # Ten plik
```

## 🛠️ Instalacja

1. Sklonuj repozytorium lub pobierz pliki:
   ```bash
   git clone <repo-url>
   cd project
   ```
2. Utwórz folder `src` i zapisz w nim:
   - `gch.sss` (nadaj prawa: `chmod +x src/gch.sss`)
   - `recordwebskocet.rs`
3. Zainstaluj zależności Pythona:
   ```bash
   pip install -r requirements.txt
   ```
   (lub ręcznie: `pip install requests python-whois dnspython paramiko beautifulsoup4 websocket-client colorama`)
4. Zainstaluj Rust i zależności:
   ```bash
   rustup update
   cargo add ipgeolocate reqwest tokio serde
   ```

## 🚀 Użycie

1. Uruchom skrypt:
   ```bash
   python network_analyzer.py
   ```
2. Użyj komend w interfejsie CLI:
   ```
   >> analyze https://example.com    # Analiza strony
   >> rhost example.com            # Analiza zdalnego hosta
   >> ehost localhost             # Analiza lokalnego hosta
   >> clear                       # Czyści terminal
   >> help                        # Wyświetla pomoc
   >> exit                        # Zamyka program
   ```

## 📸 Zrzut ekranu

Czy chcesz, abym wygenerował obraz zrzutu ekranu interfejsu? (Potwierdź, a przygotuję mockup w PNG).

*Placeholder dla zrzutu ekranu:*
![Zrzut ekranu](path/to/screenshot.png) <!-- Wstaw ścieżkę po wygenerowaniu -->

## 🛡️ Uwagi dotyczące bezpieczeństwa

- **Etyka**: Używaj narzędzia wyłącznie na serwerach, do których masz uprawnienia. Nielegalne skanowanie jest niezgodne z prawem. 🚨
- **Logi**: Wyniki zapisywane są w `network_analysis_log.txt` dla audytu.
- **Ograniczenia**: Narzędzie nie zawiera exploitów ani funkcji do ataków (np. XSS, SQLi).

## 👥 Twórca

- **@ArsagrdKronos** 🧑‍💻


## 📜 Licencja

[MIT License](LICENSE) - Wolno używać, modyfikować i dystrybuować zgodnie z zasadami licencji.

## 🌟 Podziękowania

Dziękujemy społeczności open-source za narzędzia takie jak `colorama`, `ipgeolocate`, `reqwest` oraz wszystkim testerom i współtwórcom! 🙌

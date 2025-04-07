import socket
import requests
from ftplib import FTP
import threading
from colorama import Fore, Style

# Seznam vrat za skeniranje (dodani še drugi priljubljeni porti)
ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432]  # FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, NetBIOS, HTTPS, SMB, MySQL, RDP, PostgreSQL

# Globalna spremenljivka za rezultate
results = []

# Funkcija za preverjanje odprtih vrat
def check_open_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

# Funkcija za preverjanje verzije storitve (HTTP, FTP, SSH, SMTP, DNS...)
def get_service_version(ip, port):
    try:
        if port == 80 or port == 443:  # HTTP/HTTPS
            response = requests.get(f"http://{ip}:{port}", timeout=3)
            if "Server" in response.headers:
                return response.headers["Server"]
            return "Unknown HTTP version"
        elif port == 21:  # FTP
            ftp = FTP()
            ftp.connect(ip, port, timeout=3)
            banner = ftp.getwelcome()
            return banner.split()[1]  # Prva beseda v FTP bannerju je običajno različica
        elif port == 22:  # SSH
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8")
            return banner.split("\n")[0]  # SSH banner običajno vsebuje različico
        elif port == 23:  # Telnet
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8")
            return banner.split("\n")[0]  # Telnet banner običajno vsebuje različico
        elif port == 25:  # SMTP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8")
            return banner.split("\n")[0]  # SMTP banner običajno vsebuje različico
        elif port == 53:  # DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b'\x00\x00\x00\x00')  # Pošlje DNS poizvedbo
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            return "DNS service" if banner else "Unknown DNS version"
        elif port == 110:  # POP3
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8")
            return banner.split("\n")[0]  # POP3 banner običajno vsebuje različico
        elif port == 139 or port == 445:  # SMB
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            return "SMB service" if banner else "Unknown SMB version"
        elif port == 3306:  # MySQL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8")
            return banner.split("\n")[0]  # MySQL banner običajno vsebuje različico
        elif port == 3389:  # RDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            return "RDP service" if banner else "Unknown RDP version"
        elif port == 5432:  # PostgreSQL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8")
            return banner.split("\n")[0]  # PostgreSQL banner običajno vsebuje različico
        else:
            return "Unknown service"
    except Exception as e:
        return f"Error: {str(e)}"

# Funkcija za skeniranje odprtih vrat
def scan_ports(ip):
    for port in ports:
        if check_open_port(ip, port):
            print(Fore.GREEN + f"✅ Port {port} is open." + Style.RESET_ALL)
            version = get_service_version(ip, port)
            print(Fore.YELLOW + f"    Version/Service: {version}" + Style.RESET_ALL)
            results.append((port, version))
        else:
            print(Fore.RED + f"❌ Port {port} is closed." + Style.RESET_ALL)

# Funkcija za začetek skeniranja z več nitmi
def run_scan(ip):
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_ports, args=(ip,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

    print(Fore.CYAN + "\nScan complete!" + Style.RESET_ALL)
    for port, version in results:
        print(f"Port {port} - Service Version: {version}")

# Glavna funkcija za zagon skeniranja
def run():
    print(Fore.CYAN + "Starting port scan..." + Style.RESET_ALL)
    ip = input("Enter target IP address: ")
    run_scan(ip)


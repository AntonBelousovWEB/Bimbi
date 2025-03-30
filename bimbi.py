import argparse
import os
import secrets
import socket
import threading
import time
import requests
import socks
import curses
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import config

server_stats = {
    "clients": 0,
    "messages": 0,
    "current_ip": "N/A",
    "ip_changes": 0,
    "hostname": "Не указан"
}

client_connections = []
lock = threading.Lock()

def load_hostname():
    try:
        with open(config.HOSTNAME_PATH, "r") as file:
            server_stats["hostname"] = file.read().strip()
    except Exception as e:
        server_stats["hostname"] = f"Ошибка: {e}"

def generate_key():
    return secrets.token_bytes(16)

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + encrypted

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size)
    return decrypted.decode()

def get_tor_ip():
    session = requests.Session()
    session.proxies = {
        "http": f"socks5h://127.0.0.1:{config.SOCKS_PORT}", 
        "https": f"socks5h://127.0.0.1:{config.SOCKS_PORT}"
    }
    try:
        ip = session.get("http://check.torproject.org/api/ip").json()["IP"]
        with lock:
            server_stats["current_ip"] = ip
        return ip
    except Exception as e:
        return "Ошибка"

def change_tor_ip():
    try:
        with socket.socket() as tor_control_socket:
            tor_control_socket.connect(('127.0.0.1', config.CONTROL_PORT))
            tor_control_socket.send(b'AUTHENTICATE "<your_password>"\n')
            response = tor_control_socket.recv(1024)
            if b"250" not in response:
                return False
            tor_control_socket.send(b"signal NEWNYM\r\n")
            response = tor_control_socket.recv(1024)
            if b"250" not in response:
                return False
            with lock:
                server_stats["ip_changes"] += 1
            return True
    except Exception:
        return False

def broadcast_message(sender_socket, message_data, key):
    with lock:
        for client in client_connections:
            if client != sender_socket:
                try:
                    encrypted_message = encrypt_message(key, message_data)
                    client.send(encrypted_message)
                except:
                    pass

def handle_client(client_socket, key):
    try:
        auth_data = client_socket.recv(1024)
        if not auth_data:
            client_socket.close()
            return
        
        try:
            decrypted_auth = decrypt_message(key, auth_data)
            if decrypted_auth != "AUTH_OK":
                client_socket.close()
                return
        except:
            client_socket.close()
            return

        client_socket.send(b"AUTH_SUCCESS")

        with lock:
            server_stats["clients"] += 1
            client_connections.append(client_socket)
        
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            
            with lock:
                server_stats["messages"] += 1

            message = decrypt_message(key, data)
            broadcast_message(client_socket, message, key)
    except:
        pass
    finally:
        with lock:
            server_stats["clients"] -= 1
            if client_socket in client_connections:
                client_connections.remove(client_socket)
        client_socket.close()

def server_statistics_display(ip_change_interval, key):
    stdscr = curses.initscr()
    curses.noecho()
    curses.curs_set(0)
    stdscr.nodelay(1)

    try:
        while True:
            stdscr.clear()
            stdscr.addstr(1, 20, "=== Информация и Статистика ===")
            stdscr.addstr(3, 20, f"Ключ подключения: {key.hex()}")
            stdscr.addstr(4, 20, f"Текущий IP: {server_stats['current_ip']}")
            stdscr.addstr(5, 20, f"Подключения: {server_stats['clients']}")
            stdscr.addstr(6, 20, f"Смен IP: {server_stats['ip_changes']}")
            stdscr.addstr(7, 20, f"Сообщения: {server_stats['messages']}")
            stdscr.addstr(8, 20, f"Hostname: {server_stats['hostname']}")
            stdscr.addstr(10, 20, f"Команда для подключения:")
            stdscr.addstr(12, 20, f"python bimbi.py -mode client -k {key.hex()} -server_ip {server_stats['hostname']}")
            stdscr.refresh()
            time.sleep(1)
    except:
        curses.endwin()

def start_server(port, key, ip_change_interval):
    load_hostname()
    server = socks.socksocket()
    server.set_proxy(socks.SOCKS5, "127.0.0.1", config.SOCKS_PORT)
    server.bind(("0.0.0.0", port))
    server.listen(5)

    get_tor_ip()

    threading.Thread(target=server_statistics_display, args=(ip_change_interval, key), daemon=True).start()

    def ip_updater():
        while True:
            time.sleep(ip_change_interval)
            if change_tor_ip():
                get_tor_ip()
    
    threading.Thread(target=ip_updater, daemon=True).start()

    print(f"[Сервер] Запущен на порту {port}")
    print(f"[Сервер] Ключ подключения: {key.hex()}")
    
    while True:
        client_sock, addr = server.accept()
        print(f"[Сервер] Новое подключение от {addr}")
        threading.Thread(target=handle_client, args=(client_sock, key)).start()

def start_client(server_ip, port, key):
    client = socks.socksocket()
    client.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    
    last_message_time = 0

    def receive_messages():
        while True:
            try:
                data = client.recv(1024)
                if not data:
                    print("[Клиент] Соединение с сервером потеряно")
                    break
                
                if data == b"AUTH_SUCCESS":
                    continue
                
                message = decrypt_message(key, data)
                print(f"\n[Клиент] Получено сообщение: {message}")
                print("Введите сообщение: ", end="", flush=True)
            except Exception as e:
                print(f"\n[Клиент] Ошибка при получении: {e}")
                break
    
    try:
        print("[Клиент] Пытаюсь подключиться...")
        client.connect((server_ip, port))
        
        auth_message = encrypt_message(key, "AUTH_OK")
        client.send(auth_message)
        
        auth_response = client.recv(1024)
        if auth_response != b"AUTH_SUCCESS":
            print("[Клиент] Неверный ключ! Соединение закрыто.")
            client.close()
            return
        
        print("[Клиент] Успешная аутентификация")
        
        threading.Thread(target=receive_messages, daemon=True).start()
        
        while True:
            message = input("Введите сообщение: ")

            if not message.strip():
                print("[ОШИБКА] Сообщение не может быть пустым. Пожалуйста, введите хотя бы один символ.")
                continue
            
            if message.lower() == "exit":
                break

            current_time = time.time()
            time_since_last_message = current_time - last_message_time
            
            if time_since_last_message < config.DELAY_TIME and last_message_time > 0:
                wait_time = config.DELAY_TIME - time_since_last_message
                print(f"[ОШИБКА] Пожалуйста, подождите {wait_time:.1f} секунд перед отправкой следующего сообщения.")
                time.sleep(wait_time)

            encrypted_message = encrypt_message(key, message)
            client.send(encrypted_message)
            last_message_time = time.time()
    except Exception as e:
        print(f"Ошибка клиента: {e}")
    finally:
        client.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-mode", type=str, required=True, choices=["server", "client"], help="Режим работы: server или client")
    parser.add_argument("-k", type=str, required=True, help="Ключ шифрования (random для генерации)")
    parser.add_argument("-ip", type=int, default=10, help="Время смены IP (сек)")
    parser.add_argument("-server_ip", type=str, default="127.0.0.1", help="IP-адрес сервера (для клиента)")
    args = parser.parse_args()
    
    key = generate_key() if args.k == "random" else bytes.fromhex(args.k)
    port = config.PORT
    if args.mode == "server":
        start_server(port, key, args.ip)
    else:
        start_client(args.server_ip, port, key)

if __name__ == "__main__":
    main()

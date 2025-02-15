import socket
import threading
import paramiko
import os
from sqlite3 import IntegrityError
from secrets import token_hex
from db import create_tables, insert_login_data, insert_command_data
from logger import log_event

MOTD = """UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED

You must have explicit, authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities performed on this device are logged and monitored.\n"""


# Host key (auto-generated if not exists)
HOST_KEY_FILE = "honeypot_host.key"
if not os.path.exists(HOST_KEY_FILE):
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(HOST_KEY_FILE)
else:
    host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.session_id = token_hex(8)
        self.username = None
        self.password = None
        self.pubkey = None

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password

        if password:
            try:
                insert_login_data(self.session_id, username, password=password)
            except IntegrityError:
                log_event("Collision in session_id, regenerating...")
                self.session_id = token_hex(8)
                insert_login_data(self.session_id, username, password=password)

            log_event(
                f"Login attempt: {username} with password: {password} session_id: {self.session_id}"
            )

            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.username = username

        if key:
            self.pubkey = key.get_base64()
            try:
                insert_login_data(self.session_id, username, pubkey=self.pubkey)
                log_event(
                    f"Login attempt: {username} with public key: {self.pubkey} session_id: {self.session_id}"
                )
            except IntegrityError:
                log_event("Collision in session_id, regenerating...")
                self.session_id = token_hex(8)
                insert_login_data(self.session_id, username, pubkey=self.pubkey)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        log_event(f"Command executed: {command}")
        channel.send(f"Command received: {command}\n")
        insert_command_data(self.session_id, command)
        return True


def handle_client(client):
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    server = HoneypotServer()
    transport.start_server(server=server)
    channel = transport.accept(20)
    if channel is None:
        log_event("Channel connection failed.")
        return

    log_event("Client connected.")
    server.event.wait(10)

    channel.send(MOTD)
    prompt = f"{server.username}@localhost $ "

    try:
        while True:
            channel.send(prompt)
            command = channel.recv(1024).decode("utf-8").strip()
            if not command:
                continue
            log_event(f"Client executed: {command}")
            insert_command_data(server.session_id, command)
            if command.lower() in ["exit", "quit"]:
                channel.send("Goodbye!\n")
                break
            channel.send(f"Unknown command: {command}\n")
    except Exception as e:
        log_event(f"Error: {e}")
    finally:
        channel.close()
        transport.close()
        log_event("Client disconnected.")


def start_honeypot(host="0.0.0.0", port=2222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    log_event(f"Honeypot listening on {host}:{port}")

    while True:
        client, addr = server_socket.accept()
        log_event(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()


if __name__ == "__main__":
    create_tables()
    start_honeypot()

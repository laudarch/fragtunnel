#!/usr/bin/env python3

import sys
import socket
import threading
import queue
import time
import traceback
import getopt

BUFFER_SIZE = 8192
FRAGMENT_SIZE = 1024

CONFIG = {
    "SECRET_KEY": b"",
    "ENCRYPTED": False,
    "VERBOSE": False,
    "TARGET_SET": False,
    "TARGET_IP": "",
    "TARGET_PORT": 0,
    "TUNNEL_IP": "",
    "TUNNEL_PORT": 0,
    "LOCAL_PORT": 0,
    "BIND_IP": ""
}

SERVER_BUFFERS = {
    "IN": queue.Queue(),
    "OUT": queue.Queue(),
    "CLIENT_SOCKET": None
}

def log(msg):
    if CONFIG["VERBOSE"]:
        print(msg)


def xor_data(data: bytes, key: bytes) -> bytes:
    extended_key = key * (len(data) // len(key)) + key[:len(data) % len(key)]
    return bytes(a ^ b for a, b in zip(data, extended_key))


def encrypt(data: bytes) -> bytes:
    return xor_data(data, CONFIG["SECRET_KEY"]) if CONFIG["ENCRYPTED"] else data


def decrypt(data: bytes) -> bytes:
    return xor_data(data, CONFIG["SECRET_KEY"]) if CONFIG["ENCRYPTED"] else data


class FragmentManager:
    """Handles splitting and rejoining byte streams."""

    def __init__(self):
        self.fragments = []
        self.index = 0

    def fragment(self, data: bytes):
        payload = encrypt(data)
        self.fragments = [payload[i:i+FRAGMENT_SIZE] for i in range(0, len(payload), FRAGMENT_SIZE)]
        self.index = 0

    def next(self):
        if self.index < len(self.fragments):
            frag = self.fragments[self.index]
            self.index += 1
            return frag
        return None

    def append(self, data: bytes):
        self.fragments.append(data)

    def join(self) -> bytes:
        return decrypt(b''.join(self.fragments))

    def clear(self):
        self.fragments = []
        self.index = 0


class FragTunnel:
    """Tunnel framing and special messages."""

    EOD = b"###>EOD<###"
    ACK = b"###>ACK<###"
    ERR = b"###>ERR<###"
    TARGET = b"####>TARGETIP:PORT<####"

    @staticmethod
    def send(s, msg: bytes):
        s.sendall(encrypt(msg))

    @staticmethod
    def recv(s) -> dict:
        raw = s.recv(FRAGMENT_SIZE)
        if not raw:
            return {"status": None, "data": None}

        data = decrypt(raw)
        try:
            if data == FragTunnel.EOD:
                return {"status": "EOD"}
            elif data == FragTunnel.ACK:
                return {"status": "ACK"}
            elif data == FragTunnel.ERR:
                return {"status": "ERR"}
            elif data.startswith(FragTunnel.TARGET):
                return {"status": "TARGET", "data": data}
            else:
                return {"status": "DATA", "data": raw}
        except UnicodeDecodeError:
            return {"status": "DATA", "data": raw}


def local_server():
    """Handles local connections to the tunnel."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', CONFIG["LOCAL_PORT"]))
        server.listen(5)
        log(f"[+] Local server listening on port {CONFIG['LOCAL_PORT']}")
        while True:
            conn, addr = server.accept()
            log(f"[+] New local connection: {addr}")
            tunnel = open_tunnel()
            threading.Thread(target=handle_client, args=(conn, tunnel), daemon=True).start()


def handle_client(local_sock, tunnel_sock):
    """Bidirectional transfer between local socket and tunnel."""
    frag_mgr = FragmentManager()
    try:
        local_sock.setblocking(False)
        tunnel_sock.setblocking(False)

        while True:
            try:
                data = local_sock.recv(BUFFER_SIZE)
                if not data:
                    break

                frag_mgr.fragment(data)
                while (frag := frag_mgr.next()):
                    FragTunnel.send(tunnel_sock, frag)
                FragTunnel.send(tunnel_sock, FragTunnel.EOD)

            except BlockingIOError:
                pass

            resp = FragTunnel.recv(tunnel_sock)
            if resp["status"] == "DATA":
                frag_mgr.append(resp["data"])
                FragTunnel.send(tunnel_sock, FragTunnel.ACK)
            elif resp["status"] == "EOD":
                local_sock.sendall(frag_mgr.join())
                frag_mgr.clear()
                FragTunnel.send(tunnel_sock, FragTunnel.EOD)
            elif resp["status"] is None:
                break

    finally:
        local_sock.close()
        tunnel_sock.close()


def open_tunnel():
    """Establish tunnel connection and optionally send target info."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((CONFIG["TUNNEL_IP"], CONFIG["TUNNEL_PORT"]))
    log("[+] Tunnel connection established.")

    if not CONFIG["TARGET_SET"]:
        FragTunnel.send(s, FragTunnel.TARGET + f"{CONFIG['TARGET_IP']}:{CONFIG['TARGET_PORT']}".encode())
        ack = FragTunnel.recv(s)
        if ack["status"] == "ACK":
            CONFIG["TARGET_SET"] = True
        else:
            FragTunnel.send(s, FragTunnel.ERR)
            s.close()
            raise RuntimeError("Failed to set target.")
    return s


def tunnel_server():
    """Tunnel server that proxies tunnel clients to a single target."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((CONFIG["BIND_IP"], CONFIG["TUNNEL_PORT"]))
        server.listen(5)
        log(f"[+] Tunnel server listening on {CONFIG['BIND_IP']}:{CONFIG['TUNNEL_PORT']}")

        while True:
            conn, addr = server.accept()
            log(f"[+] Tunnel client connected: {addr}")
            threading.Thread(target=handle_tunnel_client, args=(conn,), daemon=True).start()


def handle_tunnel_client(conn):
    frag_mgr = FragmentManager()
    try:
        resp = FragTunnel.recv(conn)
        if resp["status"] == "TARGET":
            _, target = resp["data"].split(b":")
            CONFIG["TARGET_IP"], CONFIG["TARGET_PORT"] = target.decode().split(":")
            CONFIG["TARGET_PORT"] = int(CONFIG["TARGET_PORT"])
            SERVER_BUFFERS["CLIENT_SOCKET"] = socket.create_connection((CONFIG["TARGET_IP"], CONFIG["TARGET_PORT"]))
            FragTunnel.send(conn, FragTunnel.ACK)

        client_sock = SERVER_BUFFERS["CLIENT_SOCKET"]

        while True:
            try:
                inbound = client_sock.recv(BUFFER_SIZE)
                if inbound:
                    frag_mgr.fragment(inbound)
                    while (frag := frag_mgr.next()):
                        FragTunnel.send(conn, frag)
                    FragTunnel.send(conn, FragTunnel.EOD)
            except BlockingIOError:
                pass

            resp = FragTunnel.recv(conn)
            if resp["status"] == "DATA":
                frag_mgr.append(resp["data"])
                FragTunnel.send(conn, FragTunnel.ACK)
            elif resp["status"] == "EOD":
                client_sock.sendall(frag_mgr.join())
                frag_mgr.clear()
                FragTunnel.send(conn, FragTunnel.EOD)

    finally:
        conn.close()
        if SERVER_BUFFERS["CLIENT_SOCKET"]:
            SERVER_BUFFERS["CLIENT_SOCKET"].close()


def parse_args():
    opts, _ = getopt.getopt(sys.argv[1:], "ht:T:p:b:e:v", ["help", "target=", "tunnelTo=", "port=", "bind=", "encrypt=", "verbose"])
    for opt, val in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-t", "--target"):
            CONFIG["TARGET_IP"], CONFIG["TARGET_PORT"] = val.split(":")[0], int(val.split(":")[1])
        elif opt in ("-T", "--tunnelTo"):
            CONFIG["TUNNEL_IP"], CONFIG["TUNNEL_PORT"] = val.split(":")[0], int(val.split(":")[1])
        elif opt in ("-p", "--port"):
            CONFIG["LOCAL_PORT"] = int(val)
        elif opt in ("-b", "--bind"):
            CONFIG["BIND_IP"], CONFIG["TUNNEL_PORT"] = val.split(":")[0], int(val.split(":")[1])
        elif opt in ("-e", "--encrypt"):
            CONFIG["ENCRYPTED"] = True
            CONFIG["SECRET_KEY"] = val.encode()
        elif opt in ("-v", "--verbose"):
            CONFIG["VERBOSE"] = True


def usage():
    print(f"Usage: {sys.argv[0]} -p <local port> -t <target ip:port> -T <tunnel ip:port> -b <bind ip:port> -e <secret> -v")
    sys.exit(0)


if __name__ == "__main__":
    parse_args()
    if CONFIG["LOCAL_PORT"] and CONFIG["TUNNEL_IP"] and CONFIG["TARGET_IP"]:
        local_server()
    elif CONFIG["BIND_IP"]:
        tunnel_server()

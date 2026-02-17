import json
import socket
from typing import Any, Dict

def send_json(conn: socket.socket, obj: Dict[str, Any]) -> None:
    """
    Envía un objeto JSON usando un framing simple:
    4 bytes big-endian con la longitud + payload UTF-8.
    """
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    length = len(data).to_bytes(4, byteorder="big")
    conn.sendall(length + data)

def recv_json(conn: socket.socket) -> Dict[str, Any]:
    """
    Recibe un objeto JSON con framing: primero 4 bytes longitud, luego payload.
    """
    header = recvall(conn, 4)
    if not header:
        raise ConnectionError("Conexión cerrada (sin cabecera).")
    length = int.from_bytes(header, byteorder="big")
    payload = recvall(conn, length)
    if not payload:
        raise ConnectionError("Conexión cerrada (sin payload).")
    return json.loads(payload.decode("utf-8"))

def recvall(conn: socket.socket, n: int) -> bytes:
    """
    Lee exactamente n bytes del socket (o menos si se cierra la conexión).
    """
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf

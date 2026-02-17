import socket
from datetime import datetime
from pathlib import Path

from protocol import recv_json, send_json
from storage import add_user, verify_user
from crypto_utils import make_session_id, make_session_key_hex, hmac_sha256_hex, secure_eq_hex
from session_store import SessionStore

HOST = "127.0.0.1"
PORT = 5000
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "server.log"

SESSIONS = SessionStore()


def log(msg: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = f"{datetime.now().isoformat(timespec='seconds')} | {msg}"
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)


def build_transfer_mac_message(session_id: str, nonce: str, payload: str) -> str:
    return f"{session_id}|{nonce}|{payload}"


def handle_request(req: dict) -> dict:
    req_type = req.get("type")

    if req_type == "PING":
        return {"status": "OK", "echo": req}

    if req_type == "REGISTER":
        username = (req.get("username") or "").strip()
        password = req.get("password") or ""

        if not username or not password:
            return {"status": "ERROR", "error": "MISSING_FIELDS"}

        try:
            add_user(username, password)
            return {"status": "OK", "msg": "USER_REGISTERED"}
        except ValueError as e:
            return {"status": "ERROR", "error": str(e)}

    if req_type == "LOGIN":
        username = (req.get("username") or "").strip()
        password = req.get("password") or ""

        if not username or not password:
            return {"status": "ERROR", "error": "MISSING_FIELDS"}

        ok = verify_user(username, password)
        if not ok:
            return {"status": "ERROR", "error": "INVALID_CREDENTIALS"}

        session_id = make_session_id()
        session_key_hex = make_session_key_hex()
        SESSIONS.create(session_id, username, session_key_hex)

        return {
            "status": "OK",
            "msg": "LOGIN_OK",
            "session_id": session_id,
            "session_key": session_key_hex,
        }

    if req_type == "TRANSFER":
        session_id = req.get("session_id") or ""
        nonce = req.get("nonce") or ""
        payload = req.get("payload") or ""
        mac = req.get("mac") or ""

        if not session_id or not nonce or not payload or not mac:
            return {"status": "ERROR", "error": "MISSING_FIELDS"}

        sess = SESSIONS.get(session_id)
        if not sess:
            return {"status": "ERROR", "error": "INVALID_SESSION"}

        if SESSIONS.nonce_seen(session_id, nonce):
            return {"status": "ERROR", "error": "REPLAY_DETECTED"}

        msg = build_transfer_mac_message(session_id, nonce, payload)
        expected_mac = hmac_sha256_hex(sess.session_key_hex, msg)

        if not secure_eq_hex(mac, expected_mac):
            return {"status": "ERROR", "error": "BAD_MAC"}

        SESSIONS.mark_nonce(session_id, nonce)
        log(f"TRANSFER aceptada (user={sess.username}) payload={payload}")

        return {"status": "OK", "msg": "TRANSFER_ACCEPTED"}

    return {"status": "ERROR", "error": "UNKNOWN_REQUEST"}


def main() -> None:
    log(f"Arrancando servidor en {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)

        log("Esperando conexión...")
        conn, addr = s.accept()

        with conn:
            log(f"Cliente conectado desde {addr}")

            while True:
                try:
                    req = recv_json(conn)
                except Exception:
                    log("Conexión cerrada por el cliente.")
                    break

                log(f"Recibido JSON: {req}")
                resp = handle_request(req)
                send_json(conn, resp)
                log(f"Respuesta enviada: {resp}")

    log("Servidor finalizado.")


if __name__ == "__main__":
    main()


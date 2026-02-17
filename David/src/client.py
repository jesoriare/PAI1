import socket
from protocol import send_json, recv_json
from crypto_utils import make_nonce_hex, hmac_sha256_hex

HOST = "127.0.0.1"
PORT = 5000


def main() -> None:
    username = "david"
    password = "password123"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # 1) LOGIN
        send_json(s, {"type": "LOGIN", "username": username, "password": password})
        login_resp = recv_json(s)
        print("LOGIN resp:", login_resp)

        if login_resp.get("status") != "OK":
            return

        session_id = login_resp["session_id"]
        session_key = login_resp["session_key"]

        # 2) TRANSFER
        nonce = make_nonce_hex()
        payload = "CuentaOrigen,CuentaDestino,100"

        msg = f"{session_id}|{nonce}|{payload}"
        mac = hmac_sha256_hex(session_key, msg)

        transfer_req = {
            "type": "TRANSFER",
            "session_id": session_id,
            "nonce": nonce,
            "payload": payload,
            "mac": mac,
        }

        send_json(s, transfer_req)
        transfer_resp = recv_json(s)
        print("TRANSFER resp:", transfer_resp)


if __name__ == "__main__":
    main()

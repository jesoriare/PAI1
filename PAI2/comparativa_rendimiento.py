import socket
import ssl
import threading
import time
import datetime
import os
import hashlib
import argparse

HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 3443
CERT_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "certs", "cert.pem")

conexiones_exitosas = 0
conexiones_fallidas = 0
lock = threading.Lock()


def huella_certificado(path):
    with open(path, "rb") as f:
        pem = f.read().decode("utf-8")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def cliente_tls(host, port, cert_path, tls_info):
    global conexiones_exitosas, conexiones_fallidas
    contexto_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto_tls.minimum_version = ssl.TLSVersion.TLSv1_3
    contexto_tls.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        contexto_tls.set_ciphersuites(
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
        )
    except AttributeError:
        pass
    contexto_tls.check_hostname = False
    contexto_tls.verify_mode = ssl.CERT_REQUIRED
    contexto_tls.load_verify_locations(cert_path)

    try:
        sock_raw = socket.create_connection((host, port), timeout=5)
        sock_tls = contexto_tls.wrap_socket(sock_raw, server_hostname=host)

        esperado = huella_certificado(cert_path)
        presentado = hashlib.sha256(sock_tls.getpeercert(binary_form=True)).hexdigest()
        if presentado != esperado:
            sock_tls.close()
            raise ssl.SSLError("Huella de certificado no coincide (posible MitM)")

        with lock:
            conexiones_exitosas += 1
            if tls_info["valor"] is None:
                tls_info["valor"] = f"version={sock_tls.version()} cipher={sock_tls.cipher()}"
        sock_tls.close()
    except Exception:
        with lock:
            conexiones_fallidas += 1


def cliente_raw(host, port):
    global conexiones_exitosas, conexiones_fallidas
    try:
        sock = socket.create_connection((host, port), timeout=5)
        with lock:
            conexiones_exitosas += 1
        sock.close()
    except Exception:
        with lock:
            conexiones_fallidas += 1


def lanzar_prueba(modo, host, port, usuarios, cert_path):
    tls_info = {"valor": None}
    hilos = []
    inicio = time.time()

    for _ in range(usuarios):
        if modo == "tls":
            hilo = threading.Thread(
                target=cliente_tls, args=(host, port, cert_path, tls_info)
            )
        else:
            hilo = threading.Thread(target=cliente_raw, args=(host, port))
        hilos.append(hilo)
        hilo.start()

    for hilo in hilos:
        hilo.join()

    fin = time.time()
    duracion = fin - inicio

    print("\n" + "=" * 40)
    print(f"RESULTADOS ({modo.upper()})")
    print("=" * 40)
    print(f"Tiempo total en atender a {usuarios} usuarios: {duracion:.4f} segundos")
    print(f"Conexiones exitosas: {conexiones_exitosas}")
    print(f"Conexiones fallidas: {conexiones_fallidas}")
    if modo == "tls":
        print(f"TLS: {tls_info['valor']}")
    print("=" * 40)

    ts = datetime.datetime.now().isoformat(timespec="seconds")
    linea = (
        f"{ts} | modo={modo} | usuarios={usuarios} | "
        f"duracion_s={duracion:.4f} | "
        f"exitosas={conexiones_exitosas} | "
        f"fallidas={conexiones_fallidas} | "
        f"tls={tls_info['valor']}\n"
    )
    with open("evidencias_comparativa.log", "a", encoding="utf-8") as f:
        f.write(linea)


def main():
    parser = argparse.ArgumentParser(description="Comparativa TLS vs RAW")
    parser.add_argument("--modo", choices=["tls", "raw"], required=True)
    parser.add_argument("--host", default=HOST_DEFAULT)
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    parser.add_argument("--usuarios", type=int, default=300)
    parser.add_argument("--cert", default=CERT_PATH_DEFAULT)
    args = parser.parse_args()

    lanzar_prueba(args.modo, args.host, args.port, args.usuarios, args.cert)


if __name__ == "__main__":
    main()

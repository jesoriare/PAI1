import socket
import ssl
import threading
import time
import datetime
import os
import hashlib

HOST = '127.0.0.1'
PORT = 3443
NUM_USUARIOS = 300
MAX_USUARIOS = 1000
PASO_USUARIOS = 100
CERT_PATH = os.path.join(os.path.dirname(__file__), 'certs', 'cert.pem')

# Variables para medir el rendimiento
conexiones_exitosas = 0
conexiones_fallidas = 0
tiempo_total = 0
tls_info = None

# Candado para que los hilos no se pisen al sumar
lock = threading.Lock()

def huella_certificado(path):
    with open(path, 'rb') as f:
        pem = f.read().decode('utf-8')
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def cliente_robot(id_robot):
    global conexiones_exitosas, conexiones_fallidas, tls_info
    
    # 1. Configurar contexto TLS del cliente robot
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
    contexto_tls.load_verify_locations(CERT_PATH)

    try:
        # 2. Intentar conectar al servidor
        sock_raw = socket.create_connection((HOST, PORT), timeout=5)
        sock_tls = contexto_tls.wrap_socket(sock_raw, server_hostname=HOST)
        
        # Verificacion adicional por huella (pinning estricto)
        esperado = huella_certificado(CERT_PATH)
        presentado = hashlib.sha256(sock_tls.getpeercert(binary_form=True)).hexdigest()
        if presentado != esperado:
            sock_tls.close()
            raise ssl.SSLError("Huella de certificado no coincide (posible MitM)")

        # Conexion exitosa (Handshake TLS superado)
        with lock:
            conexiones_exitosas += 1
            if tls_info is None:
                tls_info = f"version={sock_tls.version()} cipher={sock_tls.cipher()}"
            
        # Cerramos educadamente
        sock_tls.close()
        
    except Exception as e:
        with lock:
            conexiones_fallidas += 1

def ejecutar_prueba(num_usuarios):
    global conexiones_exitosas, conexiones_fallidas, tls_info
    conexiones_exitosas = 0
    conexiones_fallidas = 0
    tls_info = None

    print(f"Iniciando prueba de estres: {num_usuarios} empleados concurrentes...")
    hilos = []

    inicio = time.time()

    for i in range(num_usuarios):
        hilo = threading.Thread(target=cliente_robot, args=(i,))
        hilos.append(hilo)
        hilo.start()

    for hilo in hilos:
        hilo.join()

    fin = time.time()
    duracion = fin - inicio

    print("\n" + "="*40)
    print("RESULTADOS DE LA PRUEBA DE RENDIMIENTO")
    print("="*40)
    print(f"Tiempo total en atender a {num_usuarios} usuarios: {duracion:.4f} segundos")
    print(f"Conexiones exitosas (TLS): {conexiones_exitosas}")
    print(f"Conexiones fallidas: {conexiones_fallidas}")
    print("="*40)

    ts = datetime.datetime.now().isoformat(timespec="seconds")
    linea = (
        f"{ts} | usuarios={num_usuarios} | "
        f"duracion_s={duracion:.4f} | "
        f"exitosas={conexiones_exitosas} | "
        f"fallidas={conexiones_fallidas} | tls={tls_info}" + os.linesep
    )
    with open("evidencias_estres.log", "a", encoding="utf-8", newline="") as f:
        f.write(linea)

    return conexiones_fallidas


def lanzar_prueba():
    usuarios = NUM_USUARIOS
    while usuarios <= MAX_USUARIOS:
        fallidas = ejecutar_prueba(usuarios)
        if fallidas > 0:
            print(f"\nFallo detectado con {usuarios} usuarios concurrentes.")
            break
        usuarios += PASO_USUARIOS

if __name__ == "__main__":
    lanzar_prueba()







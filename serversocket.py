import socket
import ssl
import threading
import hashlib
import json
import jwt
import datetime
import hmac
import os
import logging

# -----------------------------
# CONFIGURACIÓN DE LOS LOGS (Profesional y persistente)
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    handlers=[
        # Forzamos encoding UTF-8 para que las tildes y símbolos se vean bien
        logging.FileHandler("evidencias_servidor.log", encoding='utf-8'), 
        logging.StreamHandler() 
    ]
)

# -----------------------------
# CONFIGURACIÓN Y CONSTANTES
# -----------------------------
HOST = "localhost"
PORT = 3443

DATABASE_FILE = "bd/usuarios.json"
TRANSACCIONES_FILE = "bd/transacciones.json"
TOKENS_FILE = "bd/tokens.json"
SALTS_FILE = "bd/salts.json"

SECRET_KEY = "TokenSecurityTeam9SSII"
base = "SSIISecurityTeam9"
HMAC_KEY = hashlib.sha256(base.encode()).digest()

# -----------------------------
# CARGA INICIAL DE DATOS
# -----------------------------
try:
    if not os.path.exists("bd"): os.makedirs("bd")
    with open(DATABASE_FILE, "r") as file:
        usuarios = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
    usuarios = {}

try:
    with open(TRANSACCIONES_FILE, "r") as file:
        transacciones = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
    transacciones = []

try:
    with open(SALTS_FILE, "r") as file:
        salts = json.load(file)
except:
    salts = {}

# Limpiamos tokens activos al reiniciar el servidor.
tokens_activos = {}
nonces_usados = set()

# -----------------------------
# FUNCIONES DE UTILIDAD
# -----------------------------
def guardar_usuarios():
    with open(DATABASE_FILE, "w") as file:
        json.dump(usuarios, file, indent=4)

def guardar_salts():
    with open(SALTS_FILE, "w") as file:
        json.dump(salts, file, indent=4)

def guardar_transacciones():
    with open(TRANSACCIONES_FILE, "w") as file:
        json.dump(transacciones, file, indent=4)

def guardar_tokens():
    with open(TOKENS_FILE, "w") as file:
        json.dump(tokens_activos, file, indent=4)

def generar_token(usuario):
    payload = {
        "usuario": usuario,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    tokens_activos[token] = usuario
    guardar_tokens()
    logging.info(f"Token de sesión generado exitosamente para el usuario: {usuario}")
    return token

def verificar_token(token):
    if token not in tokens_activos:
        logging.warning("Intento de uso de token no activo o expirado.")
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["usuario"]
    except Exception as e:
        logging.error(f"Error al verificar token: {e}")
        return None

def cerrar_sesion(token):
    usuario = verificar_token(token)
    if usuario:
        tokens_activos.pop(token, None)
        guardar_tokens()
        logging.info(f"Sesión cerrada con éxito para el usuario {usuario}.")
        return f"Sesión cerrada con éxito para el usuario {usuario}."
    else:
        return "Error en el servidor. Es necesario iniciar sesión de nuevo."

def calcular_mac(clave, mensaje):
    return hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256).hexdigest()

def enviar_respuesta_segura(conn, mensaje):
    nonce_resp = os.urandom(16).hex()
    mac_resp = calcular_mac(HMAC_KEY, f"{nonce_resp}:{mensaje}")
    conn.send(f"SEGURO:{nonce_resp}:{mac_resp}:{mensaje}".encode())

# -----------------------------
# MANEJO DE SALTS Y HASH
# -----------------------------
def obtener_salt(usuario):
    if usuario not in salts:
        salts[usuario] = os.urandom(32).hex() 
        guardar_salts()
    return salts[usuario]

def hashear_contrasena(contrasena, usuario):
    salt = obtener_salt(usuario) 
    return hashlib.sha256((salt + contrasena).encode()).hexdigest()

# -----------------------------
# PROTECCIÓN DE LOGIN (BLOQUEO IP)
# -----------------------------
intentos_fallidos = {} 
lockout_time = 600  

# -----------------------------
# MANEJO DE CLIENTES
# -----------------------------
def manejar_cliente(conn, addr):
    logging.info(f"Nueva conexión establecida desde {addr}")
    try:
        while True:
            datos = conn.recv(4096)
            if not datos: break

            mensaje = datos.decode()
            partes = mensaje.split(":")
            accion = partes[0] if len(partes) > 0 else None
            
            logging.info(f"Petición recibida: {accion}")

            if accion == "REGISTRO":
                usuario, contrasena = partes[1], partes[2]
                if usuario in usuarios:
                    conn.send("Usuario ya registrado".encode())
                else:
                    usuarios[usuario] = hashear_contrasena(contrasena, usuario)
                    guardar_usuarios()
                    conn.send("Usuario registrado exitosamente".encode())
                    logging.info(f"Registro exitoso: Nuevo usuario '{usuario}' creado.")

            elif accion == "LOGIN":
                usuario, contrasena = partes[1], partes[2]
                client_ip = addr[0]

                if client_ip in intentos_fallidos:
                    ultimo_intento, intentos = intentos_fallidos[client_ip]
                    if intentos >= 4 and (datetime.datetime.now() - ultimo_intento).seconds < lockout_time:
                        logging.warning(f"BLOQUEO DE SEGURIDAD: IP {client_ip} rechazada por exceso de intentos.")
                        conn.send("Demasiados intentos fallidos. Inténtelo en 10 minutos.".encode())
                        continue

                if usuario in usuarios and hashear_contrasena(contrasena, usuario) == usuarios[usuario]:
                    token = generar_token(usuario)
                    conn.send(f"Inicio de sesión exitoso:{token}".encode())
                    intentos_fallidos.pop(client_ip, None)
                    logging.info(f"Login exitoso: Usuario '{usuario}' autenticado.")
                else:
                    intentos = intentos_fallidos.get(client_ip, (None, 0))[1] + 1
                    intentos_fallidos[client_ip] = (datetime.datetime.now(), intentos)
                    logging.warning(f"Login fallido: Intento {intentos} para el usuario '{usuario}' desde {client_ip}")
                    conn.send(f"Inicio de sesión fallido. Intentos restantes: {4-intentos}".encode())

            elif accion == "TRANSACCION":
                token, cuenta_origen, cuenta_destino, cantidad, nonce, mac_recibido = partes[1:7]
                usuario_actual = verificar_token(token)

                if not usuario_actual:
                    conn.send("Error en el servidor. Es necesario iniciar sesión de nuevo.".encode())
                    continue

                # 1. VERIFICACIÓN ANTI-REPLAY
                if nonce in nonces_usados:
                    logging.warning(f"ATAQUE DE REPLAY DETECTADO: Nonce repetido '{nonce}' enviado desde {addr}")
                    enviar_respuesta_segura(conn, "Error: Nonce repetido (posible replay)")
                    continue
                nonces_usados.add(nonce)

                # 2. VERIFICACIÓN ANTI-MITM (INTEGRIDAD)
                contenido = f"{nonce}:{token}:{cuenta_origen}:{cuenta_destino}:{cantidad}"
                mac_calculado = calcular_mac(HMAC_KEY, contenido)
                
                if not hmac.compare_digest(mac_calculado, mac_recibido):
                    logging.warning(f"FALLO DE INTEGRIDAD (MitM): MAC inválido en transacción de usuario '{usuario_actual}'")
                    conn.send("Error: MAC inválido (posible manipulación de datos)".encode())
                    continue

                # --- NUEVA VALIDACIÓN DE DATOS ---
                try:
                    cant_float = float(cantidad)
                    if cant_float <= 0:
                        logging.warning(f"OPERACION INVALIDA: El usuario {usuario_actual} intento transferir cantidad no permitida: {cant_float}")
                        conn.send("Error: La cantidad debe ser un numero mayor que 0.".encode())
                        continue
                except ValueError:
                    logging.warning(f"ERROR DE FORMATO: Cantidad no numerica recibida: {cantidad}")
                    conn.send("Error: El formato de la cantidad es incorrecto.".encode())
                    continue
                # ---------------------------------

                # 3. TRANSACCIÓN EXITOSA (Solo llegamos aquí si el importe es > 0)
                transacciones.append({
                    "usuario": usuario_actual, 
                    "cuenta_origen": cuenta_origen,
                    "cuenta_destino": cuenta_destino,
                    "cantidad": cant_float, 
                    "timestamp": datetime.datetime.now().isoformat()
                })
                guardar_transacciones()
                
                logging.info(f"TRANSACCION SEGURA: {usuario_actual} envio {cant_float} EUR de {cuenta_origen} a {cuenta_destino} (Integridad Verificada).")
                enviar_respuesta_segura(conn, "Transferencia realizada correctamente.")
    except Exception as e:
        logging.error(f"Error durante la comunicación con {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"Cliente desconectado: {addr}")

# -----------------------------
# INICIO DEL SERVIDOR
# -----------------------------
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORT))
        servidor.listen()
        servidor.settimeout(1.0)
        logging.info(f"Arrancando servidor en {HOST}:{PORT}")

        while True:
            try:
                conn, addr = servidor.accept()
                threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()
            except (socket.timeout, TimeoutError): 
                pass
            except KeyboardInterrupt:
                logging.info("Servidor apagado manualmente de forma segura.")
                break

if __name__ == "__main__":
    main()
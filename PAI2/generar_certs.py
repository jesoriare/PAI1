import os
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generar_certificados():
    # 1. Crear carpeta certs si no existe
    if not os.path.exists('certs'):
        os.makedirs('certs')
        print("Carpeta 'certs' creada.")

    print("Generando clave privada RSA 4096... (puede tardar un par de segundos)")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    print("Generando certificado autofirmado...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Andalucia"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecurityTeam9"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Válido por 1 año
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    # 2. Guardar la Clave Privada (key.pem)
    with open("certs/key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 3. Guardar el Certificado (cert.pem)
    with open("certs/cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("¡ÉXITO! Certificados 'cert.pem' y 'key.pem' generados correctamente en la carpeta 'certs/'.")

if __name__ == "__main__":
    generar_certificados()
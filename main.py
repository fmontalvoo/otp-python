import hmac
import hashlib
import time

def generate_otp(secret_key, interval=30, digits=6):
    # Obtenemos el tiempo actual en segundos
    current_time = int(time.time())
    # Dividimos el tiempo actual en intervalos
    counter = current_time // interval

    # Convertimos el contador en una cadena de bytes
    counter_bytes = counter.to_bytes(8, byteorder='big')
    
    # Convertimos la clave secreta en una cadena de bytes
    secret_key_bytes = secret_key.encode('utf-8')

    # Calculamos el HMAC-SHA1 del contador usando la clave secreta
    hmac_digest = hmac.new(secret_key_bytes, counter_bytes, hashlib.sha1).digest()

    # Obtenemos el índice del último byte para generar el código de verificación
    offset = hmac_digest[-1] & 0x0F
    truncated_hash = hmac_digest[offset:offset+4]

    # Convertimos los bytes en un entero
    binary_code = int.from_bytes(truncated_hash, byteorder='big')

    # Aplicamos una máscara para obtener el código de verificación de la longitud deseada
    otp = binary_code % (10 ** digits)

    # Rellenamos con ceros a la izquierda si es necesario
    otp_str = str(otp).zfill(digits)

    return otp_str

def validate_otp(secret_key, otp, interval=30, digits=6, window=1):
    # Obtenemos el tiempo actual en segundos
    current_time = int(time.time())
    
    for i in range(-window, window+1):
        # Calculamos el contador para el intervalo de tiempo actual y el desplazamiento
        counter = (current_time // interval) + i
        
        # Convertimos el contador en una cadena de bytes
        counter_bytes = counter.to_bytes(8, byteorder='big')

        # Convertimos la clave secreta en una cadena de bytes
        secret_key_bytes = secret_key.encode('utf-8')

        # Calculamos el HMAC-SHA1 del contador usando la clave secreta
        hmac_digest = hmac.new(secret_key_bytes, counter_bytes, hashlib.sha1).digest()

        # Obtenemos el índice del último byte para generar el código de verificación
        offset = hmac_digest[-1] & 0x0F
        truncated_hash = hmac_digest[offset:offset+4]

        # Convertimos los bytes en un entero
        binary_code = int.from_bytes(truncated_hash, byteorder='big')

        # Aplicamos una máscara para obtener el código de verificación de la longitud deseada
        generated_otp = binary_code % (10 ** digits)

        # Rellenamos con ceros a la izquierda si es necesario
        generated_otp_str = str(generated_otp).zfill(digits)

        # Comparamos el código OTP generado con el código proporcionado
        if otp == generated_otp_str:
            return True
    
    return False

# Ejemplo de uso
secret_key = "mi_clave_secreta"
otp = generate_otp(secret_key)
print("Código OTP actual:", otp)

valid = validate_otp(secret_key, otp)

if valid:
    print("La clave OTP es válida.")
else:
    print("La clave OTP no es válida.")
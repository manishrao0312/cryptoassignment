import os
import base64
import json
import io
import zlib
from flask import Flask, request, jsonify
import qrcode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__, static_url_path='', static_folder='static')

# Serve frontend
@app.route('/')
def index():
    return app.send_static_file('index.html')

# ----------------------------
# ECC Key Generation (Bob)
# ----------------------------
bob_private_key = ec.generate_private_key(ec.SECP256R1())
bob_public_key = bob_private_key.public_key()

# ----------------------------
# Encryption Function (Alice)
# ----------------------------
def encrypt_message(message: bytes):
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), bob_public_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-encryption'
    ).derive(shared_secret)

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag

    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {
        'ephemeral_pub': base64.b64encode(ephemeral_pub_bytes).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    }

    # Compress payload for QR
    payload_json = json.dumps(payload).encode()
    compressed_payload = base64.b64encode(zlib.compress(payload_json)).decode()

    # Generate QR
    qr_io = io.BytesIO()
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=12,
        border=4
    )
    qr.add_data(compressed_payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(qr_io, 'PNG')
    qr_io.seek(0)

    return payload, qr_io, ephemeral_pub_bytes, aes_key, compressed_payload

# ----------------------------
# Decryption Function (Bob)
# ----------------------------
def decrypt_message(payload):
    ephemeral_pub_bytes = base64.b64decode(payload['ephemeral_pub'])
    iv = base64.b64decode(payload['iv'])
    ciphertext = base64.b64decode(payload['ciphertext'])
    tag = base64.b64decode(payload['tag'])

    ephemeral_pub_key = serialization.load_pem_public_key(ephemeral_pub_bytes)
    shared_secret = bob_private_key.exchange(ec.ECDH(), ephemeral_pub_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-encryption'
    ).derive(shared_secret)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# ----------------------------
# Routes
# ----------------------------
@app.route('/bob_keys', methods=['GET'])
def bob_keys():
    pub_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = bob_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return jsonify({
        "public_key": pub_bytes.decode(),
        "private_key": priv_bytes.decode()
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    message = data.get('message', '')
    if not message:
        return jsonify({'error': 'Message is required'}), 400

    payload, qr_io, ephemeral_pub_bytes, aes_key, compressed_payload = encrypt_message(message.encode())
    bob_pub_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return jsonify({
        "payload": payload,
        "qr_image": base64.b64encode(qr_io.getvalue()).decode(),
        "bob_public_key": bob_pub_bytes.decode(),
        "ephemeral_public_key": ephemeral_pub_bytes.decode(),
        "aes_key_demo": base64.b64encode(aes_key).decode(),
        "compressed_payload": compressed_payload
    })

@app.route('/encrypt_payload', methods=['POST'])
def encrypt_payload():
    # Returns payload JSON without QR
    data = request.json
    message = data.get('message', '')
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    payload, _, ephemeral_pub_bytes, aes_key, _ = encrypt_message(message.encode())
    bob_pub_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({
        "payload": payload,
        "bob_public_key": bob_pub_bytes.decode(),
        "ephemeral_public_key": ephemeral_pub_bytes.decode(),
        "aes_key_demo": base64.b64encode(aes_key).decode()
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    payload = request.json.get('payload')
    if not payload:
        return jsonify({'error': 'Payload is required'}), 400
    try:
        plaintext = decrypt_message(payload)
        return jsonify({'message': plaintext.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ----------------------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)

from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['message'].encode()

    # Generate AES key and cipher
    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)

    # Encrypt the message
    encrypted_message = cipher.encrypt(message)

    # Encrypt AES key using RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    return render_template(
        'result.html',
        original=message.decode(),
        encrypted=encrypted_message.decode(),
        aes_key=aes_key.decode(),
        encrypted_key=str(encrypted_aes_key)
    )

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    encrypted_message = request.form['encrypted'].encode()
    encrypted_aes_key = eval(request.form['encrypted_key'])

    # Decrypt AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Decrypt message
    cipher = Fernet(aes_key)
    decrypted_message = cipher.decrypt(encrypted_message)

    return render_template(
        'result.html',
        decrypted=decrypted_message.decode(),
        encrypted=request.form['encrypted'],
        aes_key=aes_key.decode()
    )

if __name__ == '__main__':
    app.run(debug=True)
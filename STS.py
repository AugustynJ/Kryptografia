from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode


def sign_message(message, priv_key):
    key = RSA.importKey(priv_key)
    digest = SHA256.new()
    digest.update(message.encode('utf-8'))
    signer = PKCS1_v1_5.new(key)
    sig = signer.sign(digest)
    return sig.hex()


def verify(message, signature, pub_key):
    key = RSA.importKey(pub_key)
    print("signature", signature)
    sig = bytes.fromhex(signature).decode('utf-8')
    # str(sig)
    digest = SHA256.new()
    digest.update(message.encode('utf-8'))
    verifier = PKCS1_v1_5.new(pub_key)
    verified = verifier.verify(digest, sig)
    if verified:
        return True
    else:
        print("Weryfikacja się nie powiodła")
        return False


def encrypt(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


def decrypt(message, priv_key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message)


# https: // the-it-ninja.blogspot.com/2015/11/station-to-station-encryption-in -python.html

# Ustalenie losowej stałej
g = 4

# Utworzenie klucza publicznego i prywatnego Alice
key_1 = RSA.generate(1024)
A_priv_key = key_1.exportKey('PEM')
A_pub_key = key_1.publickey().exportKey('PEM')


key_2 = RSA.generate(1024)
B_priv_key = key_2.exportKey('PEM')
B_pub_key = key_2.publickey().exportKey('PEM')


# Alice wybiera liczbe x,liczy g^x i przesyła Bobowi
x = 10
g_x = g ** x
print(f"Alice wybiera liczbe x={x}\nliczy g^x={g_x} \ni przesyła Bobowi\n")

# Bob wybiera liczbe y,liczy g^y
y = 25
g_y = g ** y
g_xy = g_x ** y

print(
    f"Bob wybiera liczbe y={y}\nliczy (g^x)^y={g_xy}\nnastępnie podpisuje ten składnik swoim kluczem prywatnym i przesyła Alice wraz z g^y\n")
# podpisany hash w postaci szestnastkowej
g_xy_signed = sign_message(str(g_xy), B_priv_key)

print(g_xy_signed)

# Następnie Alice dostaje podpisaną wiadomość przez Boba, sprawdza jej poprawność i oblicza x Boba

g_xy_alice = g_x * g_y
if verify(g_xy_alice, g_xy_signed, B_pub_key):
    print("Udana weryfikacja")

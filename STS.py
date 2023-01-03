from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Random import random
import base64
import hashlib


def sign(message, priv_key):
    key = RSA.importKey(priv_key)
    # hash = SHA256.new(message)
    h = hashlib.new('sha256')
    h.update(bytes(str(message), 'utf-8'))
    # hash = sha256(message_encoded)
    # to_return = PKCS1_OAEP.new(key)
    return sign(h, priv_key).encode("base64")


def verify(message, signature, pub_key):
    key = RSA.importKey(pub_key)
    hash = SHA256.new(message)
    if PKCS1_OAEP.new(key).verify(hash, base64.b64decode(signature)):
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
g = 4200

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
print(f"Alice wybiera liczbe x {x},liczy g^x {g_x} i przesyła Bobowi")

# Bob wybiera liczbe y,liczy g^y
y = 25
g_xy = g_x ** y

print(g_xy)
print(
    f"Bob wybiera liczbe y {y},liczy (g^x)^y {g_xy}, następnie podpisuje ten składnik swoim kluczem prywatnym i przesyła Alice")
print(B_priv_key)
g_xy_signed = sign(str(g_xy), B_priv_key)

# Następnie Alice dostaje podpisaną wiadomość przez Boba, sprawdza jej poprawność i oblicza x Boba
x_alice = g_xy**(1/y)
if verify(x_alice, g_xy_signed, B_pub_key):
    pass

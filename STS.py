import rsa


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-256')


def verify(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key,) == 'SHA-256'
    except:
        return False


# Utworzenie klucza publicznego i prywatnego Alice
pub_key, priv_key = rsa.newkeys(1024)
a = priv_key.save_pkcs1('PEM')
a2 = pub_key.save_pkcs1('PEM')
alice_priv_key = rsa.PrivateKey.load_pkcs1(a)
alice_pub_key = rsa.PublicKey.load_pkcs1(a2)

# Utworzenie klucza publicznego i prywatnego Boba
pub_key_2, priv_key_2 = rsa.newkeys(1024)
b = priv_key_2.save_pkcs1('PEM')
b2 = pub_key_2.save_pkcs1('PEM')
bob_priv_key = rsa.PrivateKey.load_pkcs1(b)
bob_pub_key = rsa.PublicKey.load_pkcs1(b2)


# Ustalenie losowej stałej
g = 4

# Krok 1.
# Alice wybiera liczbe x, liczy g^x i przesyła Bobowi w formie zaszyfrowanej kluczem publicznym Boba
x = 2
g_x = g ** x
g_x_encrypted = encrypt(str(g_x), bob_pub_key)


# Krok 2.
# Bob otrzymuje wiadomość od Alice, wybiera liczbe y, liczy g^y i przesyła g^y oraz odszyfrowaną g^x Alice w formie zaszyfrowanej kluczem publicznym Alice
y = 2
g_y = g ** y
g_x_decrypted_bob = decrypt(g_x_encrypted, bob_priv_key)


g_x_encrypted_bob = encrypt(g_x_decrypted_bob, alice_pub_key)  # bytes
g_y_encrypted_bob = encrypt(str(g_y), alice_pub_key)  # bytes


# Krok 3.
# Alice otrzymuje zaszyfrowaną wiadomość od Boba i odszyfrowuje ją za pomocą klucza publicznego Boba i upewnia się, że faktycznie nadawcą jest Bob

g_x_decrypted_alice = decrypt(g_x_encrypted_bob, alice_priv_key)

if int(g_x_decrypted_alice) == g_x:
    print("Alice ma pewność, że faktycznie nadawcą jest Bob")
else:
    print("Alice nie ma pewności, że faktycznie nadawcą jest Bob")

# Alice szyfruje otrzymaną wartość g^y kluczem publicznym Boba a następnie ją przesyła.

g_y_decrypted_alice = decrypt(g_y_encrypted_bob, alice_priv_key)  # str

g_y_encrypted_alice = encrypt(str(g_y_decrypted_alice), bob_pub_key)  # bytes


# Krok 4.
# Alice na podstawie dostępnych wartości g^x i g^y generuje klucz sesji
g_xy_alice = int(g_y_decrypted_alice) ** int(g_x)


# Krok 5.
# Bob otrzymuję wiadomość, odszyfrowuję ją swoim kluczem prywatnym
# Na podstawie dostępnych wartości g^x i g^y generuje klucz sesji
g_y_decrypted_bob = decrypt(g_y_encrypted_alice, bob_priv_key)

if int(g_y_decrypted_bob) == g_y:
    print("Bob ma pewność, że faktycznie nadawcą jest Alice")
else:
    print("Bob nie ma pewności, że faktycznie nadawcą jest alice")

g_xy_bob = int(g_y) ** int(g_x_decrypted_bob)

# Od tej pory możliwa jest dalsza komunikacja używając nowego klucza szyfrującego

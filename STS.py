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
g_xy_signed = sign(str(g_xy), bob_priv_key)

print(g_xy_signed)

# Następnie Alice dostaje podpisaną wiadomość przez Boba, sprawdza jej poprawność i oblicza x Boba

if verify(str(g_xy), g_xy_signed, bob_pub_key):
    print("Udana weryfikacja")

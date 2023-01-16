from math import inf
import random
from Crypto.Util.number import getPrime

class Point():
    def __init__(self, x, y):
        self.x = x
        self.y = y
        
    def __str__(self):
        return f'({self.x}, {self.y})'

def sum_points(P: Point, Q: Point, a, b, m) -> Point:
    R = Point(0, 0)
    
    if(P.x == Q.x and P.y == Q.y):
        s = ((3*(P.x**2) + a) * pow(2*P.y, -1, m))
        s %= m
        R.x = s**2 - 2*P.x
        R.y = (-1)*(P.y + s*(R.x - P.x))
        
    elif(P.x != Q.x):
        s = (Q.y - P.y) * pow((Q.x - P.x), -1, m)
        s %= m
        R.x = s**2 - P.x - Q.x
        R.y = (-1)*P.y + s*(P.x - R.x)
        
    elif(P.x == Q.x):
        R.x, R.y = inf, inf
        
    R.x %= m
    R.y %= m
    return R

def multiply_point(P: Point, k, a, b, m) -> Point:
    R = P
    i = 1
    while(i < k):
        R = sum_points(R, P, a, b, m)
        i += 1
    return R
    

# Wybieranie początkowych parametrów
# y^2 = x^3 + ax + b    mod m
a, b, m = 9, 17, getPrime(16)
while True:
    try:
        G_x = random.randint(1, m-1)
        G_y = (G_x**3 + a*G_x + b) % m

        G = Point(G_x, G_y)                    # musi należeć do krzywej

        d_A = random.randint(1, m-1)        # Klucze prywatne, tajne
        d_B = random.randint(1, m-1)

        G_A = multiply_point(G, d_A, a, b, m)        # Klucze publiczne, jawne
        G_B = multiply_point(G, d_B, a, b, m)

        Key_A = multiply_point(G_B, d_A, a, b, m)    # Wyliczanie umówionego klucza
        Key_B = multiply_point(G_A, d_B, a, b, m)

        print("Klucz wyliczony przez Alicje: ", Key_A, "\nKlucz wyliczony przez Boba:   ", Key_B) 
        break
    except TypeError:
        pass
print("\nKlucze prywatne:\nA: ", d_A, "\nB: ", d_B)

###################################################################################################
# Próba łamania
# Przechwycone: G, m, G_A, G_B
# Do złamania: d_A, d_B
# Metoda: bruteforce

i = 2
while True:
    try:
        forced = multiply_point(G, i, a, b, m)
    except TypeError:
        continue
    if(forced.x == G_A.x and forced.y == G_A.y):
        print("Udało sie złamać! Klucz prywatny jednego z użytkowników wynosi: ", i)
        Key = multiply_point(G_B, i, a, b, m)
        print(f"Klucz wyliczony przez użytkowników: ({Key.x}, {Key.y})")
        break
    
    i += 1
    if(not i%100):
        print (i)


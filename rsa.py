
import math, random


def setkeys():
    prime_1 = 19  
    prime_2 = 29 

    n = prime_1 * prime_2
    phi_n = (prime_1 - 1) * (prime_2 - 1)

    
    e = random.choice([x for x in range(2, phi_n) if math.gcd(x, phi_n) == 1])
    
 
    d = pow(e, -1, phi_n)  

    return e, d, n


def encrypt(message, public_key, n):
    return pow(message, public_key, n)

def decrypt(encrypted_text, private_key, n):
    return pow(encrypted_text, private_key, n)


def encoder(message, public_key, n):
    return [encrypt(ord(letter), public_key, n) for letter in message]


def decoder(encoded, private_key, n):
    return ''.join(chr(decrypt(num, private_key, n)) for num in encoded)

#Emma Weisgerber
#CSCI 737: Intro to Cyber Security - Dr. Brian Drawert
#Homework 2: Cryptography - 2/18/19
#-----------------------------------------------------
#Program which implements the Elliptic Curve Diffie Hellman key exchange
#Using the parameters G = (5, 1), p = 17, a = 2, b = 2, n = 19, we asume Bob has beta = 2 as his secret number and alice has alpha = 18 as her secret number
#The program calculates the point B as beta*G and A as aplha*G, and shows that using either beta*A or alpha*B it results in the same point P
#Then, we use the x-cord of P as the multiplier and y-cord of P as the offset and use the affine cipher from task2 to decrypt the the task3 encrypted message
#Equations were taken from the video on the Elliptic Curve Diffie Hellman exchange, and stack overflow and man pages were referenced
#-----------------------------------------------------
#Modified for Networking Lab2 - 4/16/19

import string
from task2 import decrypt
from task2 import encrypt

def elliptic_curve_key_exchange():
    G = [5, 1] #Generator Point
    p = 17 #Field(Modulop)
    a = 2 #Curve parameter
    b = 2 #Curve parameter
    n = 19 #Ord(G)

    beta = 2 #Bob's private key
    alpha = 18 #Alice's private key
    
    A = create_public_key(alpha, G, a, p, n)
    print("Point A: {}".format(A))
    B = create_public_key(beta, G, a, p, n)
    print("Point B: {}".format(B))

    Pa = create_shared_private_key(alpha, B, a, p, n)
    Pb = create_shared_private_key(beta, A, a, p, n)
    if Pa == Pb:
        print("Point P: {}". format(Pa))
    else:
        print("Points did not match!")


    multiplier = Pa[0]
    offset = Pa[1]

    with open("task3_encrypted_message.txt", "r") as input_message:
        encrypted_message = input_message.read()
        decrypted_message = decrypt(encrypted_message, multiplier, offset)

    with open("task3_decrypted_message.txt", "w") as output_message:
        output_message.write(decrypted_message)

    with open("test_encryption.txt", "w") as test:
        test.write(encrypt(decrypted_message, multiplier, offset))


#Creates the shared private key P, using the user's private key and public key recieved from the other user
def create_shared_private_key(private_key, received_public_key, a, p, n):
    return scalar_multiple(private_key, received_public_key, a, p, n)


#Creates the public key A or B to be shared with the other user and used to created the shared private key, using the user's private key and the generator point
def create_public_key(private_key, G, a, p, n):
        return scalar_multiple(private_key, G, a, p, n)


#Function to compute point doubling: R = 2G
def point_doubling(G, a, p):
    Gx = G[0]
    Gy = G[1]

    s = ( ((3*(Gx**2) + a) % p) * modular_multiplicative_inverse(2*Gy, p) ) % p
    x = (s**2 - 2*Gx) % p
    y = (s*(Gx - x) - Gy) % p

    R = [x, y]
    return R


#Function to compute the adition of two points: R = P + Q
def addition_of_two_points(P, Q, a, p):
    Px = P[0]
    Py = P[1]
    Qx = Q[0]
    Qy = Q[1]

    if (Px - Qx) == 0:
        return [0, 0]

    s = ((Py - Qy) * modular_multiplicative_inverse(Px - Qx, p)) % p
    x = (s**2 - (Px + Qx)) % p
    y = (s*(Px - x) - Py) % p

    R = [x, y]
    return R
 

#Function to compute scalar multiplication: R = kG
def scalar_multiple(k, G, a, p, n):
    #If k is greated than n, use k mod n to ensure it's on the curve
    if k > n:
        k = k % n

    if k == 0:
        return [0, 0]

    if k == 1:
        return G

    if k == 2:
        return point_doubling(G, a, p)

    if k > 2:
        G_new = point_doubling(G, a, p)
        for i in range(k - 2):
            G_new = addition_of_two_points(G_new, G, a, p)
        return G_new


#Works only when p is prime, found on stack overflow
def modular_multiplicative_inverse(a, p):
    return a**(p - 2) % p


if __name__ == "__main__":
    elliptic_curve_key_exchange()

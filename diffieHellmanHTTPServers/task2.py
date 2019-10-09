#Emma Weisgerber
#CSCI 373: Intro to Cyber Security - Dr. Brian Drawert
#Homework 2: Cryptography - 2/18/19
#-----------------------------------------------------
#Program which implements the Affine substitution cypher
#Uses the character set of ASCII code 32 through 126 for a total of 95 characters, and ignores the new line character
#Using a multiplyer of 13 and an offset of 7 it reads in the task2 encrypted message and writes out the decrypted message
#Stack overflow and man pages were referenced
#-----------------------------------------------------
#Modified for Networking Lab2 - 4/16/19

import string

multiplier_list = [1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 18, 21, 22, 23, 24, 26, 27, 28, 29, 31, 32, 33, 34, 36, 37, 39]

def affine_cipher():
    multiplier = 13
    offset = 7

    with open("task2_encrypted_message.txt", "r") as input_message:
        encrypted_message = input_message.read()
        decrypted_message = decrypt(encrypted_message, multiplier, offset)

    with open("task2_decrypted_message.txt", "w") as output_message:
        output_message.write(decrypted_message)

    #Used to test encryption
    #with open("test_encryption.txt", "w") as test:
        #test.write(encrypt(decrypted_message, multiplier, offset))


def decrypt(cyphertext, multiplier_index, offset):
    key = decryption_key(multiplier_index, offset)
    character_set = [chr(i) for i in range(32, 127)]
    print("character set length {0}".format(len(character_set)))

    #For each character in the cyphertext, check to make sure it's a valid character
    for i in range(len(cyphertext)):
        if cyphertext[i] not in '\n\r'+"".join(character_set):
            print("Invalid character: '{0}'".format(cyphertext[i]))
            return

    #For each character in the cyphertext, decrypt the character using the key and replace it with the unencrypted character, ignoring the new line character
    plaintext = ''
    for i in range(len(cyphertext)):
        if (cyphertext[i] == '\n') or (cyphertext[i] == '\r'):
            plaintext += cyphertext[i]
        else:
            plaintext += key[cyphertext[i]]
    return plaintext


def decryption_key(multiplier_index, offset):
    character_set = [chr(i) for i in range(32, 127)]

    #Create key for each encrypted character with its corresponding unencrypted character within the character set
    key = {}
    for i in range(len(character_set)):
        j = ((multiplier_list[multiplier_index]*i + offset))%(len(character_set))
        key[character_set[j]] = character_set[i]
    return key


def encrypt(plaintext, multiplier_index, offset):
    key = encryption_key(multiplier_index, offset)
    character_set = [chr(i) for i in range(32, 127)]

    #For each character in the plaintext, check to make sure it's a valid character
    for i in range(len(plaintext)):
        if plaintext[i] not in '\n\r'+"".join(character_set):
            print("Invalid character: '{0}'".format(plaintext[i]))
            return

    #For each character in the plaintext, encrypt the character using the key and replace it with the encrypted character, ignoring the new line character
    cyphertext = ''
    for i in range(len(plaintext)):
        if (plaintext[i] == '\n') or (plaintext[i] == '\r'):
            cyphertext += plaintext[i]
        else:
            cyphertext += key[plaintext[i]]
    return cyphertext


def encryption_key(multiplier_index, offset):
    character_set = [chr(i) for i in range(32, 127)]

    #Create key for each character with its corresponding encrypted character within the set
    key = {}
    for i in range(len(character_set)):
        j = ((multiplier_list[multiplier_index]*i + offset))%(len(character_set))
        key[character_set[i]] = character_set[j]
    return key


if __name__ == "__main__":
    affine_cipher()

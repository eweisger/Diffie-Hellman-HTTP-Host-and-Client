#!/usr/bin/env python3

#Emma Weisgerber
#CSCI 373: Intro to Cyber Security - Dr. Brain Drawert
#Networking Lab2 - 4/16/19
#-----------------------------------------------------
#HTTP Client which implements Elliptic Curve Diffie Hellman key exchange and affine symmetric cypher to encrypt the HTTP request and response
#This uses my code from Homework2 to implement the key exchange and cypher as well as the code we did in class for the networking aspect, though modifications were made to ensure it works

import socket 
import sys
import random
from task2 import *
from task3 import *

HOST = sys.argv[1]
PORT = sys.argv[2]

PAGE = '/'

print("We well fetch '{0}{1}'".format(HOST, PAGE))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, int(PORT)))

    #Start ECC-ssl protocal
    s.sendall(b"HELLO\r\n")
    line = s.recv(1024)
    line = line.decode('utf-8', "Ignore")
    if not line.startswith('ECC_params:'):
        raise Exception("ECC-ssl protocal error")

    line = line.rstrip() #remove new line
    beginning, param = line.split(': ')
    param_list = param.split(', ')
    ecc_params = {}
    for i in param_list:
        name, value = i.split('=')
        ecc_params[name] = int(value)

    #do the ECC encryption to find B
    a = ecc_params['a']
    b = ecc_params['b']
    G = (ecc_params['G1'], ecc_params['G2'])
    p = ecc_params['p']
    n = ecc_params['n']
    A = (ecc_params['A1'], ecc_params['A2'])

    beta = random.randint(1, n)
    print(beta)
    B = create_public_key(beta, G, a, p, n)
        
    #calculate symmetric encryption key "p"
    P = create_shared_private_key(beta, A, a, p, n)
    multiplier = P[0]
    offset = P[1]

    test_enc_message = encrypt("TEST", multiplier, offset)

    #send B accross, and start encrypting
    enc_response = "ECC_response: B1={0}, B2={1}, TEST={2}\r\n".format(B[0], B[1], test_enc_message)

    s.sendall(str.encode(enc_response))

    #wait for server to say okay
    line = s.recv(1024)
    line = line.decode('utf-8', "ignore")
    print("got: {0}".format(line))
    if not line.startswith('OK'):
        raise Exception('ECC-ssl protocal error')

    #continue with http request

    http_request = "GET {0} HTTP/1.0\r\n\r\n".format(PAGE) #\r\n\r\n is what the server looks for to know request is done, the client is done talking
    
    print("HTTP request:")
    print(http_request)
    #Send request to server
    enc_http_request = str(encrypt(http_request, multiplier, offset))
    s.sendall(str.encode(enc_http_request))
    #Read all data from the server
    response_buffer = b''
    while True:
        data = s.recv(1024)
        response_buffer += data
        if len(data) == 0:
            break #Server closed connection
    
    print("HTTP response:")
    enc_response = response_buffer.decode('utf-8', "ignore")
    print("here")
    print(decrypt(enc_response, multiplier, offset))

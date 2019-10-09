#!/usr/bin/env python3

#Emma Weisgerber
#CSCI 373: Intro to Cyber Security - Dr. Brian Drawert
#Networking Lab2 - 4/16/19
#-----------------------------------------------------
#HTTP Server which implements Elliptic Curve Diffie Hellman key exchange and affine symmetric cypher to encrypt the HTTP request and response
#This uses my code from Homework2 to implement the key exchange and cypher as well as the code we did in class for the networking aspect, though modifications were made to ensure it works

import socket
import sys
import os
import datetime
import random
from task2 import *
from task3 import *


PORT = 8080
HOST = '127.0.0.1'


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        my_port = PORT
        while True:
            try:
                s.bind((HOST, my_port))
                break
            except:
                my_port += 1

        s.listen()
        print("Server up and listening on {0}:{1}".format(HOST, PORT))

        while True: #loop forver getting the next connection
            print("waiting for the next connection")
            conn, addr = s.accept()
            print("Got a connection from {0}".format(addr))
    
            try:
                with conn:
                   process_http_request(conn)
            except Exception as e:
                print("error: {0}".format(e))

            print("done with connection from {0}".format(addr))


def negotiate_ecc_ssl(conn):
    line = conn.recv(1024)
    line = line.decode('utf-8', "ignore")
    if line == "HELLO\r\n":
        print("got ECC-ssl hello")
    else:
        raise Exception("ECC-ssl error")
    #send encryption information
    a=2
    b=2
    G = (5,1)
    n = 19
    p = 17
    #select a random paoint
    alpha = random.randint(1, n)
    print(alpha)
    A = create_public_key(alpha, G, a, p, n)

    enc_info = "ECC_params: a={0}, b={1}, n={2}, p={3}, G1={4}, G2={5}, A1={6}, A2={7}\r\n".format(a ,b ,n ,p , G[0], G[1], A[0], A[1])
    print("Sending ECC-ssl params")
    print(enc_info)
    conn.sendall(str.encode(enc_info))

    #read response with 'B', calculate 'P' and see if test decryption works
    line = conn.recv(1024)
    line = line.decode('utf-8', "ignore")
    line = line.rstrip('\r\n')
    ecc_response, params = line.split(': ')
    param_list = params.split(', ')
    ecc_params = {}
    for i in param_list:
        name, value = i.split('=')
        ecc_params[name] = value

    B = (int(ecc_params['B1']), int(ecc_params['B2']))

    P = create_shared_private_key(alpha, B, a, p, n)
    multiplier = P[0]
    offset = P[1]
    
    test_message = str(decrypt(ecc_params["TEST"], multiplier, offset))

    if test_message != "TEST":
        raise Exception("ECC-ssl error: TEST does not equal '{0}', multiplier = {1}, offset = {2} ecncrypted text: '{3}'".format(test_message, multiplier, offset, ecc_params["TEST"]))

    #send OK, and start encrypting
    conn.sendall(b"OK\r\n")

    return(multiplier, offset)


def process_http_request(conn):
    
    multiplier, offset = negotiate_ecc_ssl(conn)

    buff = ''
    while True:
        data = conn.recv(1024)
        if not data:
            break
        buff += data.decode('utf-8', "ignore")
        #Check if the request is complete
        if buff.endswith("\r\n\r\n"):
            break
        #request complete
    print("Request:")
    dec_buff = decrypt(buff, multiplier, offset)
    print(dec_buff)
    response = parse_request(dec_buff)
    if not response:
        response = respond_404('')
    print("Response:")
    print(response)
    enc_response = str(encrypt(response, multiplier, offset))
    conn.sendall( str.encode(enc_response))


def parse_request(buff):
    #Check if it is a GET request
    if not buff.startswith('GET'):
        return False

    (method, uri, rest) = buff.split(' ', 2) #split out the method and URI

    #Find the uri on disk
    if uri.endswith('/'):
        uri += 'index.html' #deal with index pages

    filepath = os.getcwd() + uri
    print("Looking for file'{0}'".format(filepath))
    if os.path.isfile(filepath):
        #found 
        with open(filepath) as fd:
            return make_header("200 OK", fd.read())
    else:
        print("Not found!")
        return False


def respond_404(url):
    html = '''<!DOCTYPE html>
    <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>
    <BODY>
        <H1>404 Not Found</H1>
        <p>The request URL was not found on this server.</p>
        </BODY>
        </HTML>
    '''
    return make_header("404 Not Found", html)


def make_header(reponse_code, payload):
    header = "HTTP/1.0 {0}\r\n".format(reponse_code)
    header+= "Date: {0}\r\n".format(datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S SMT'))
    header+= "Server: my_python_server\r\n"
    header+= "Content-Length: {0}\r\n".format(len(payload))
    header+= "Connection: close\r\n"
    header+= "Content-Type: text/html\r\n"
    header+= "\r\n" #last line to end response

    return header + payload


if __name__ == "__main__":
    main()

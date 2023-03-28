#!/usr/bin/env python3

import socket
import binascii
import hashlib
import sys
from ecdsa import SigningKey, NIST256p

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 80  # The port used by the server

if len(sys.argv) > 1:
    sk = SigningKey.from_string(bytearray.fromhex(sys.argv[1]), curve=NIST256p, hashfunc = hashlib.sha256)
else:
    sk = SigningKey.generate(curve=NIST256p, hashfunc = hashlib.sha256)

vk = sk.verifying_key

print("########################################")
print("PRIV")
print(binascii.hexlify(sk.to_string()).decode())
print("PUB")
print(binascii.hexlify(vk.to_string()).decode())
print("########################################\n")

def to64(bytesToSign):
    bytessize = len(bytesToSign)

    while bytessize >= 64:
        bytessize = bytessize - 64

    bytessize = 64 - bytessize

    while bytessize > 0:
        bytesToSign.append(0x00)
        bytessize = bytessize - 1

    return bytesToSign

def sendReceive(dataToSend):
    print("SEND : " + binascii.hexlify(dataToSend).decode())
    s.send(dataToSend)
    data = s.recv(1024)
    print("RECEIVE : " + binascii.hexlify(data).decode())
    print("\n")
    return data

def sendGetNonce():
    my_bytes = bytearray()
    my_bytes.append(0x03)
    return sendReceive(my_bytes)

def sendInit(nonce):
    my_bytes  = bytearray()
    my_bytes.append(0x04)
    my_bytes.extend(nonce)
    my_bytes.extend(vk.to_string())
    bytes_to_sign = bytearray(my_bytes)
    bytes_to_sign = to64(bytes_to_sign)
    signature = sk.sign(bytes_to_sign)
    my_bytes.extend(signature)
    return sendReceive(my_bytes)

def createContainer(nonce, address, data):
    my_bytes  = bytearray()

    dataBytes = bytes(data, encoding='utf8')

    #Calculate container size (only one receiver)
    dataSize = len(dataBytes)
    size = dataSize + 169
    my_bytes.extend(size.to_bytes(4, 'big'))
    #nonce
    my_bytes.extend(nonce)
    #sender address
    my_bytes.extend(vk.to_string())
    #num of receivers
    my_bytes.append(0x01)
    #loop of receivers
    #receiver pub key
    my_bytes.extend(bytearray.fromhex(address))
    #receiver encryption key encrypted using ECDH
    #currently dummy data
    enckey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    my_bytes.extend(enckey)
    #data size
    my_bytes.extend(dataSize.to_bytes(4, 'big'))
    #data encrypted using receiver encryption key
    my_bytes.extend(dataBytes)
    #add signature
    bytes_to_sign = bytearray(my_bytes)
    bytes_to_sign = to64(bytes_to_sign)
    signature = sk.sign(bytes_to_sign)
    my_bytes.extend(signature)
    return my_bytes

def sendData(nonce, address, data):
    my_bytes  = bytearray()
    my_bytes.append(0x06)
    my_bytes.extend(createContainer(nonce, address, data))
    return sendReceive(my_bytes)

def getData(nonce):
    my_bytes  = bytearray()
    my_bytes.append(0x05)
    my_bytes.extend(nonce)
    bytes_to_sign = bytearray(my_bytes)
    bytes_to_sign = to64(bytes_to_sign)
    signature = sk.sign(bytes_to_sign)
    my_bytes.extend(signature)
    retdata = sendReceive(my_bytes)

    if len(retdata) > 18:
        print("RECEIVED FROM")
        print(binascii.hexlify(retdata[38:102]).decode())
        print("DATA")
        datalen = int.from_bytes(retdata[183:187], "big")
        print(str(retdata[187:187+datalen]))
        print("\n")

    return retdata

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    #Send get nonce
    data = sendGetNonce()

    #Send init
    data = sendInit(data[2:18])

    run = 1

    while run == 1:
        commandline = input("ENTER COMMAND: ")
        commandline_split = commandline.split()

        if commandline_split[0] == "send":
            print("SEND DATA")
            data = sendData(data[2:18], commandline_split[1], commandline_split[2])
        elif commandline_split[0] == "get":
            print("GET DATA")
            data = getData(data[2:18])
        elif commandline_split[0] == "exit":
            print("EXIT")
            run = 0
        else:
            print("UNKNOWN")
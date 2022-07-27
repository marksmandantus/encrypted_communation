import socket
import hashlib
import os
import time
import itertools
import threading
import sys
from Crypto.PublicKey import RSA
from CryptoPlus.Cipher import * 

host = "localhost"
port = 8080
FORMAT = "utf-8"
check = False
done = False

def animate():
    for i in itertools.cycle(['....','.......','..........','............']):
        if done:
            break
        sys.stdout.write('\rCHECKING IP ADDRESS AND PORT '+ i)
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write('\r -----SERVER STARTED. WAITING FOR CLIENT-----\n')
try:
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(5)
    check = True
except BaseException:
    print("-----Check Server Address or Port-----")
    check = False

if check is True:
    shutdown = False

    # printing "Server Started Message"
    thread_load = threading.Thread(target=animate)
    thread_load.start()

    time.sleep(4)
    done = True
    # binding client and address
    conn,address = server.accept()
    print ("CLIENT IS CONNECTED. CLIENT'S ADDRESS ->",address)
    print ("\n-----WAITING FOR PUBLIC KEY & PUBLIC KEY HASH-----\n")

    # public key
    passwd = conn.recv(2048)

    # string to KEY
    server_public_key = RSA.importKey(passwd)

    # hashing public key
    hash_value = hashlib.sha1(passwd)
    hex_digest = hash_value.hexdigest()

    if passwd != "":
        conn.send("EQ")   
        print(passwd)
        gethash = conn.recv(1024)
        print("\n-----HASH OF PUBLIC KEY----- \n"+gethash)
    if hex_digest == gethash:
        # creating session key
        key_128 = os.urandom(16)
        # encrypt CTR MODE session key
        en = AES.new(key_128,AES.MODE_CTR,counter = lambda:key_128)
        encrypto = en.encrypt(key_128)
        # hashing sha1
        en_object = hashlib.sha1(encrypto)
        en_digest = en_object.hexdigest()

        print ("\n-----SESSION KEY-----\n"+en_digest)

        # encrypting session key and public key
        E = server_public_key.encrypt(encrypto, 16)
        print ("\n-----ENCRYPTED PUBLIC KEY AND SESSION KEY-----\n"+str(E))
        print ("\n-----HANDSHAKE COMPLETE-----")
        conn.send(str(E))
        while True:
            # message from client
            newmess = conn.recv(1024)
            # decoding message 
            decoded = newmess.decode("hex")
            # making session key 
            key = en_digest[:16]
            print("\nENCRYPTED MESSAGE FROM CLIENT -> "+newmess)
            # decrypting message from the client
            ideaDecrypt = IDEA.new(key, IDEA.MODE_CTR, counter=lambda: key)
            dMsg = ideaDecrypt.decrypt(decoded)
            print("\n**New Message**  "+time.ctime(time.time()) +" > "+dMsg+"\n")
            mess = input("\nMessage To Client -> ")
            if mess != "":
                ideaEncrypt = IDEA.new(key, IDEA.MODE_CTR, counter=lambda : key)
                eMsg = ideaEncrypt.encrypt(mess)
                eMsg = eMsg.encode("hex").upper()
                if eMsg != "":
                    print("ENCRYPTED MESSAGE TO CLIENT-> " + eMsg)
                conn.send(eMsg)
        conn.close()
    else:
        print("\n-----PUBLIC KEY HASH DOESN'T MATCH-----\n")
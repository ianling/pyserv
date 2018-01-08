import socket
import threading
import sys
import select
from os.path import isfile
from Crypto.PublicKey import RSA

class Client(threading.Thread):
    def __init__(self,(client,address), privkey, pubkey):
        threading.Thread.__init__(self)
        self.clientSocket = client
        self.address = address
        self.privkey = privkey
        self.pubkey = pubkey
    def run(self):
        running = True
        connectionStage = 0
        while running:
            data = self.clientSocket.recv(2048).strip()
            if data:
                # connection initialization
                if connectionStage == 0: # verify banner, send pubkey
                    if data == 'RETURNBANNER':
                        connectionStage = 1
                        self.send(self.pubkey.exportKey())
                    else:
                        running = False
                elif connectionStage == 1: # receive pubkey, request challenge
                    if '-----BEGIN PUBLIC KEY-----' in data and '-----END PUBLIC KEY-----' in data:
                        clientPubkeyBeg = data.index('-----BEGIN PUBLIC KEY-----')
                        clientPubkeyEnd = data.index('-----END PUBLIC KEY-----') + 24 # 24 == length of key footer
                        clientPubkeyString = data[clientPubkeyBeg:clientPubkeyEnd]
                        self.clientPubkey = RSA.importKey(clientPubkeyString)
                        self.send_encrypted('REQUESTCHALLENGE')
                        connectionStage = 2
                    else:
                        running = False
                elif connectionStage == 2: # do challenge
                    data = self.privkey.decrypt(data)
                    self.send_encrypted(data)
                    connectionStage = 3
                elif connectionStage == 3: # TODO
                    if data == 'Yay!':
                        connectionStage = 4
                    else:
                        running = False
                else: # connection fully established
                    data = self.privkey.decrypt(data)
                    # echo back certain commands
                    if data == 'HELLO':
                        self.send_encrypted(data)
                    elif data == 'BYE':
                        self.send_encrypted(data)
                        running = False
                    # eval anything else
                    else:
                        try:
                            self.send_encrypted(str(eval(data)))
                        except:
                            self.send_encrypted('Failed to evaluate: ' + data)
            else:
                self.clientSocket.close()
                running = False
        self.clientSocket.close()


    def send(self, msg):
        self.clientSocket.send(msg)

    # encrypts msg with the client's public key and then sends it to the client
    def send_encrypted(self, msg):
        self.send(self.clientPubkey.encrypt(msg, 32)[0])

# import/generate host RSA keys
if isfile('server_hostkey') and isfile('server_hostkey.pub'):
    privkeyString = file('server_hostkey', 'r').read()
    pubkeyString = file('server_hostkey.pub', 'r').read()
    privkey = RSA.importKey(privkeyString)
    pubkey = RSA.importKey(pubkeyString)
else:
    print 'Generating new host RSA keys...'
    privkey = RSA.generate(4096)
    pubkey = privkey.publickey()
    # write them to files for future use
    privkeyString = privkey.exportKey()
    pubkeyString = pubkey.exportKey()
    privkeyFile = file('server_hostkey', 'w')
    pubkeyFile = file('server_hostkey.pub', 'w')
    privkeyFile.write(privkeyString)
    pubkeyFile.write(pubkeyString)
    privkeyFile.close()
    pubkeyFile.close()

bindaddress = 'localhost'
port = 55516
print 'Listening on ' + bindaddress + ':' + str(port)
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind((bindaddress, port))
serverSocket.listen(5)
clients = []
input = [serverSocket, sys.stdin]
running = True
while running:
    inputready,outputready,exceptready = select.select(input, [], [])
    for s in inputready:
        if s == serverSocket:
            c = Client(serverSocket.accept(),privkey,pubkey)
            c.start()
            clients.append(c)
            c.send('BANNER')
        elif s == sys.stdin:
            command = sys.stdin.readline().strip()
            if command == 'exit':
                running = False
            else:
                for client in clients:
                    client.send(command)

serverSocket.close()
for client in clients:
    client.send('BYE')
    client.join()

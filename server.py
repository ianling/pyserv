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
                if connectionStage == 0:
                    if data == 'RETURNBANNER':
                        connectionStage = 1
                        self.send(self.pubkey.exportKey())
                elif connectionStage == 1:
                    data = privkey.decrypt(data)
                    clientPubkey = RSA.importKey(data)
                    self.send(clientPubkey.encrypt(data, 32))
                    connectionStage = 3 # TODO CHANGE THIS TO 2
                elif connectionStage == 2:
                    # TODO
                    pass
                else:
                    # echo back certain commands
                    if data == 'HELLO':
                        self.send(data)
                    elif data == 'BYE':
                        self.send(data)
                        running = False
                    # eval anything else
                    else:
                        try:
                            self.clientSocket.send(str(eval(data)))
                        except:
                            self.clientSocket.send('Failed to evaluate: ' + data)
            else:
                self.clientSocket.close()
                running = False
    def send(self, msg):
        self.clientSocket.send(msg)

# import/generate host RSA keys
if isfile('server_hostkey') and isfile('server_hostkey.pub'):
    privkeyString = file('server_hostkey', 'r').read()
    pubkeyString = file('server_hostkey.pub', 'r').read()
    privkey = RSA.importKey(privkeyString)
    pubkey = RSA.importKey(pubkeyString)
else:
    print 'Generating new host RSA keys...'
    privkey = RSA.generate(16384)
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

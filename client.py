import socket
from sys import argv as args
from sys import stdin
from threading import Thread
import select
from os.path import isfile
from Crypto.PublicKey import RSA

host = args[1]
port = int(args[2])
size = 2048

# import/generate host RSA keys
if isfile('client_hostkey') and isfile('client_hostkey.pub'):
    privkeyString = file('client_hostkey', 'r').read()
    pubkeyString = file('client_hostkey.pub', 'r').read()
    privkey = RSA.importKey(privkeyString)
    pubkey = RSA.importKey(pubkeyString)
else:
    print 'Generating new host RSA keys...'
    privkey = RSA.generate(16384)
    pubkey = privkey.publickey()
    # write them to files for future use
    privkeyString = privkey.exportKey()
    pubkeyString = pubkey.exportKey()
    privkeyFile = file('client_hostkey', 'w')
    pubkeyFile = file('client_hostkey.pub', 'w')
    privkeyFile.write(privkeyString)
    pubkeyFile.write(pubkeyString)
    privkeyFile.close()
    pubkeyFile.close()

print 'Connecting to ' + host + ':' + str(port)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
input = [s, stdin]
running = True

# Connection Stages:
# 0 - Initial TCP connection established
# 1 - Banners exchanged
# 2 - Server public RSA key received, client public key sent
# 3 - Server sends client public key back, encrypted with client's public key
# 4 - Encryption negotiated, connection fully established.
connectionStage = 0

while running:
    inputready,outputready,exceptready = select.select(input, [], [])
    for i in inputready:
        if i == s:
            data = s.recv(size).strip()
            if data:
                if connectionStage == 0:
                    if data == 'BANNER':
                        print 'Sending banner...'
                        s.send('RETURNBANNER')
                        connectionStage = 1
                elif connectionStage == 1:
                    if data[0:26] == '-----BEGIN PUBLIC KEY-----':
                        # TODO: Store fingerprint of this key for host verification
                        print 'Received server public key. Importing...'
                        serverPubkey = RSA.importKey(data)
                        print 'Sending our public key...'
                        print len(serverPubkey.encrypt(pubkey.exportKey(),32))
                        s.send(serverPubkey.encrypt(pubkey.exportKey(), 32))
                        connectionStage = 2
                elif connectionStage == 2:
                    data = privkey.decrypt(data)
                    if data == pubkey.exportKey():
                        print 'Server identity verified.'
                        print 'Connection Established.'
                        connectionStage = 3

                else:
                    print 'SERVER: ' + data
                    # server acknowledging our disconnect
                    if data == 'BYE':
                        running = False
        elif i == stdin:
            command = stdin.readline().strip()
            if command == 'exit':
                running = False
            else:
                s.send(command)

# tell server we're disconnecting
s.send('BYE')
s.close()

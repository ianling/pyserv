import socket
from sys import argv as args
from sys import stdin
from threading import Thread
import select
from os.path import isfile
from Crypto.PublicKey import RSA


def encrypt(msg, key):
     return key.encrypt(msg, 32)[0]

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
    privkey = RSA.generate(4096)
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
# 2 - Public RSA keys exchanged
# 3 - Client sends server challenge
# 4 - Server responds to challenge
# 5 - Encryption negotiated, connection fully established.
connectionStage = 0

while running:
    inputready,outputready,exceptready = select.select(input, [], [])
    for i in inputready:
        if i == s:
            data = s.recv(size).strip()
            if data:
                if connectionStage == 0: # send banner
                    if data == 'BANNER':
                        print 'Sending banner...'
                        s.send('RETURNBANNER')
                        connectionStage = 1
                    else:
                        print 'Received invalid/unsupported banner from server. Disconnecting...'
                        running = False
                elif connectionStage == 1: # receive public key, send our public key
                    # TODO: Allow for RSA keys of arbitrary length (loop until key footer found
                    if '-----BEGIN PUBLIC KEY-----' in data and '-----END PUBLIC KEY-----' in data:
                        # TODO: Store fingerprint of this key for host verification
                        print 'Received server public key. Importing...'
                        serverPubkeyBeg = data.index('-----BEGIN PUBLIC KEY-----')
                        serverPubkeyEnd = data.index('-----END PUBLIC KEY-----') + 24 # 24 == length of key footer
                        serverPubkeyString = data[serverPubkeyBeg:serverPubkeyEnd]
                        serverPubkey = RSA.importKey(serverPubkeyString)
                        print 'Sending our public key...'
                        s.send(pubkey.exportKey())
                        connectionStage = 2
                    else:
                        print 'Received invalid/malformed public key from server. Disconnecting...'
                        running = False
                elif connectionStage == 2: # send challenge
                    data = privkey.decrypt(data)
                    if data == 'REQUESTCHALLENGE':
                        # TODO: randomly generate this
                        print 'Sending challenge...'
                        challengeText = 'CHALLENGE'
                        cipherText = serverPubkey.encrypt(challengeText, 32)[0]
                        s.send(cipherText)
                        connectionStage = 3
                    else:
                        print 'Server did not request host verification challenge. Disconnecting...'
                        running = False
                elif connectionStage == 3: # verify challenge
                    data = privkey.decrypt(data)
                    if data == challengeText:
                        print 'Challenge Complete.'
                        print 'Connection established.'
                        s.send('Yay!')
                        connectionStage = 4
                    else:
                        print 'Server failed host verification challenge. Disconnecting...'
                        running = False

                # connection is fully initialized
                else:
                    data = privkey.decrypt(data)
                    print 'SERVER: ' + data
                    # server acknowledging our disconnect
                    if data == 'BYE':
                        running = False
        elif i == stdin:
            command = encrypt(stdin.readline().strip(), serverPubkey)
            if command == 'exit':
                running = False
            else:
                s.send(command)

# tell server we're disconnecting
s.send('BYE')
s.close()

import socket
from sys import argv as args
from sys import stdin
from threading import Thread
import select

host = args[1]
port = int(args[2])
size = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
input = [s, stdin]
running = True
while running:
    inputready,outputready,exceptready = select.select(input, [], [])
    for i in inputready:
        if i == s:
            data = s.recv(size).strip()
            if data:
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

import socket
import threading
import sys
import select

class Client(threading.Thread):
    def __init__(self,(client,address)):
        threading.Thread.__init__(self)
        self.clientSocket = client
        self.address = address
    def run(self):
        running = True
        while running:
            data = self.clientSocket.recv(1000).strip()
            if data:
                # echo back certain commands
                if data == 'HELLO':
                    self.send(data)
                elif data == 'BYE':
                    self.send(data)
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

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(('localhost', 55516))
serverSocket.listen(5)
clients = []
input = [serverSocket, sys.stdin]
running = True
while running:
    inputready,outputready,exceptready = select.select(input, [], [])
    for s in inputready:
        if s == serverSocket:
            c = Client(serverSocket.accept())
            c.start()
            clients.append(c)
            c.send('Hello client!')
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

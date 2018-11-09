import socket
import threading



sa='0.0.0.0'
sp=9999

server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((sa,sp))
server.listen(5)

def client_handler(client_socket):
        request=client.recv(4096)
        print('[*] recieved Connection from %s'%request)
        client_socket.send(b'ACK')
        client_socket.close()

while True:
        client,addr=server.accept()
        print('Received Connection from %s:%d'%(addr[0],addr[1])
        handle_client = threading.Thread(target=client_handler, args=(client,))
        handle_client.start()

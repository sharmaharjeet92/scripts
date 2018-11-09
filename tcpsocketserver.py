import socketserver

class Ehandler(socketserver.BaseRequestHandler):

        def handle(self):
            print('Accepted Connection from: ',self.client_address)
            data = 'dummy'

            while len(data):
                data = self.request.recv(2048)
                self.request.send(data)

        print('client Left')





addr=('0.0.0.0',7000)
server = socketserver.TCPServer(addr,Ehandler)
server.serve_forever()

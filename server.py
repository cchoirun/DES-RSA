import socket
import threading
import json


clients = {}
public_keys = {}

def handle_client(client_socket, address, client_id):
    """Handles communication with a connected client."""
    try:
        print(f"Accepted connection from {address} with ID {client_id}")

        send_message(client_socket, {
            'data': f"Welcome to the server! Your ID is {client_id}",
            'client_id': client_id
        })

       
        public_key_data = receive_message(client_socket)
        public_key = public_key_data.get('public_key')

 
        notify_clients(client_id, public_key)

        send_message(client_socket, {
            'public_keys': public_keys,
            'data': "Public Keys Dictionary"
        })

        
        public_keys[client_id] = public_key

       
        while True:
            data = receive_message(client_socket)
            if not data:
                break

            print(f"Received data from {address} (ID {client_id}): {data}")

            if data.get('data') == 'L':
                send_client_list(client_socket)
            else:
                forward_message(client_id, data)

    except Exception as e:
        print(f"Error handling client {client_id}: {e}")

    finally:
        
        disconnect_client(client_id, client_socket)


def send_message(client_socket, message):
    """Sends a message to client."""
    try:
        client_socket.send(json.dumps(message).encode('utf-8'))
    except Exception as e:
        print(f"Error sending message: {e}")


def receive_message(client_socket):
    """Receives and decodes a JSON-encoded message from a client."""
    try:
        data = client_socket.recv(1024).decode('utf-8')
        return json.loads(data) if data else None
    except json.JSONDecodeError as e:
        print(f"Error decoding message: {e}")
        return None


def notify_clients(client_id, public_key):
    """Notifies all clients about a new client's public key."""
    for target_id, client_item_socket in clients.items():
        if target_id != client_id:
            send_message(client_item_socket, {
                'client_id': client_id,
                'public_key': public_key,
                'data': f"Public Key for New Client ID: {client_id}"
            })


def send_client_list(client_socket):
    """Sends a list of connected clients to a specific client."""
    connected_clients = list(clients.keys())
    send_message(client_socket, {
        'data': f"Connected clients: {connected_clients}"
    })


def forward_message(sender_id, data):
    """Forwards a message to target clients."""
    target_ids = data.get('target_ids', [])
    message = data.get('data')
    step = data.get('step')
    length = data.get('length')

    for target_id in target_ids:
        target_socket = clients.get(target_id)
        if target_socket and target_id != sender_id:
            send_message(target_socket, {
                'step': step,
                'sender_id': sender_id,
                'data': message,
                'length': length
            })


def disconnect_client(client_id, client_socket):
    """Removes a disconnected client."""
    if client_id in clients:
        del clients[client_id]
    if client_id in public_keys:
        del public_keys[client_id]

    print(f"Connection with client ID {client_id} closed.")
    client_socket.close()


def start_server(host, port):
    """Server starting and listening for connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Server listening on {host}:{port}...")

    try:
        while True:
            client_socket, addr = server.accept()
            client_id = len(clients) + 1
            clients[client_id] = client_socket

            threading.Thread(
                target=handle_client, args=(client_socket, addr, client_id)
            ).start()

    except KeyboardInterrupt:
        print("Server shutdown.")

    finally:
        
        for client_socket in clients.values():
            client_socket.close()
        server.close()


if __name__ == "__main__":
    start_server("127.0.0.1", 5001)

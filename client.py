import socket
import threading
import random
import secrets
import string
import time
import des
import rsa


def print_message_box(header, lines):
    max_line_length = max(len(line) for line in lines)
    border = "+" + "-" * (max_line_length + 2) + "+"
    header_row = f"| {header.center(max_line_length)} |"
    content_rows = [f"| {line.ljust(max_line_length)} |" for line in lines]
    print("\n".join([border, header_row, border] + content_rows + [border]))


def generate_random_string(length=16):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


def encrypt_data(data, key, modulus):
    return rsa.encoder(str(data), key, modulus)


def decrypt_data(data, key, modulus):
    return eval(rsa.decoder(data, key, modulus))


def send_message(socket, message_dict):
    socket.send(str(message_dict).encode('utf-8'))


def receive_messages(client_socket):
    global state, target_id, session_des_key, session_round_key
    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break

            data = eval(data)
            if 'public_keys' in data:
                public_keys.update(data['public_keys'])
                print_message_box("Received", [data['data']])

            elif 'public_key' in data:
                public_keys[data['client_id']] = data['public_key']
                print_message_box("Received", [data['data']])

            elif 'step' in data:
                handle_protocol_step(data, client_socket)

            else:
                print(f"\nReceived from server: {data['data']}")
    except Exception as e:
        print(f"\nError receiving messages: {e}")


def handle_protocol_step(data, client_socket):
    global state, target_id, session_des_key, session_round_key, recv_n_1, n_1, n_2

    step = data.get("step")
    sender_id = data.get("sender_id")
    decrypted_data = decrypt_data(data["data"], private_key, n)

    if step == 1:
        recv_n_1 = decrypted_data['n_1']
        response = {'n_1': recv_n_1, 'n_2': n_2}
        send_encrypted_step(client_socket, sender_id, 2, response)

    elif step == 2:
        assert n_1 == decrypted_data['n_1'], "N1 mismatch!"
        response = {'n_2': decrypted_data['n_2']}
        send_encrypted_step(client_socket, sender_id, 3, response)

    elif step == 3:
        assert n_2 == decrypted_data['n_2'], "N2 mismatch!"
        session_key_setup(decrypted_data, client_socket, sender_id)

    elif step == 4:
        session_key_setup(decrypted_data, None, sender_id, finalize=True)

    elif step == 5:
        handle_chat_message(decrypted_data, sender_id)


def send_encrypted_step(client_socket, target_id, step, data):
    encrypted_data = encrypt_data(data, public_keys[target_id], n)
    send_message(client_socket, {"step": step, "target_id": target_id, "data": encrypted_data, 'length': -1})


def session_key_setup(decrypted_data, client_socket, sender_id, finalize=False):
    global state, session_des_key, session_round_key, target_id

    if not finalize:
        session_key = generate_random_string()
        session_des_key = session_key
        session_round_key = des.generate_round_keys(des.string2bin(session_key)[0])[0]
        response = {'n_1': recv_n_1, 'k_s': session_key}
        send_encrypted_step(client_socket, sender_id, 4, response)
    else:
        session_des_key = decrypted_data['k_s']
        session_round_key = des.generate_round_keys(des.string2bin(session_des_key)[0])[0]
        print(">>> Session Acquired <<<")
        target_id = sender_id
        state = 'chat'


def handle_chat_message(data, sender_id):
    length = data['length']
    encrypted_message = data['data']
    decrypted_message = des.bin2string(
        ''.join(des.decrypt(encrypted_message[i:i+64], session_round_key) for i in range(0, len(encrypted_message), 64))
    )
    print_message_box(f"Received from {sender_id}:", [f"Decrypted: {decrypted_message[:length]}"])


if __name__ == "__main__":
    public_keys = {}
    state, target_id = "listen", None
    generated_des_key = generate_random_string()
    session_des_key, session_round_key = None, None

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5001))

    public_key, private_key, n = rsa.setkeys()
    n_1, n_2 = random.randint(1000, 9999), random.randint(1000, 9999)

    send_message(client, {"public_key": public_key})
    welcome_msg = eval(client.recv(1024).decode('utf-8'))
    print(welcome_msg['data'])

    threading.Thread(target=receive_messages, args=(client,)).start()

    try:
        while True:
            time.sleep(0.1)
            if state == 'listen':
                target_id = input("Enter target client ID or 'L' to list clients: ")
                if target_id.lower() == 'l':
                    send_message(client, {"data": 'L'})
                else:
                    target_id = int(target_id)
                    send_encrypted_step(client, target_id, 1, {'n_1': n_1, 'id_a': welcome_msg['client_id']})
            elif state == 'chat':
                message = input(f"Enter message to {target_id} ('b' to stop): ")
                if message.lower() == 'b':
                    state, target_id = 'listen', None
                else:
                    encrypted_message = ''.join(des.encrypt(chunk, session_round_key) for chunk in des.string2bin(message))
                    send_message(client, {'step': 5, 'target_id': target_id, 'length': len(message), 'data': encrypted_message})
    except KeyboardInterrupt:
        pass
    finally:
        client.close()

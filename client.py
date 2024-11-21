import asyncio
import websockets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad
import os


async def communicate():
    uri = "ws://localhost:8765"
    try:
        async with websockets.connect(uri) as websocket:
            # Terima public key dari server
            server_public_key = RSA.import_key((await websocket.recv()).encode())
            print("Kunci publik server diterima.")

            # Buat DES key dan kirim dalam bentuk terenkripsi
            des_key = os.urandom(8)
            des_cipher = DES.new(des_key, DES.MODE_ECB)
            rsa_cipher = PKCS1_OAEP.new(server_public_key)
            encrypted_des_key = rsa_cipher.encrypt(des_key)
            await websocket.send(encrypted_des_key.hex())
            print(f"DES Key terenkripsi dikirim: {encrypted_des_key.hex()}")

            # Kirim pesan ke server
            message = input("Masukkan pesan untuk Server: ").encode()
            encrypted_message = des_cipher.encrypt(pad(message, DES.block_size))
            await websocket.send(encrypted_message.hex())
            print(f"Pesan terenkripsi dikirim: {encrypted_message.hex()}")

            # Terima balasan terenkripsi dari server
            encrypted_reply = bytes.fromhex(await websocket.recv())
            decrypted_reply = unpad(des_cipher.decrypt(encrypted_reply), DES.block_size)
            print(f"Balasan dari Server: {decrypted_reply.decode()}")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")


asyncio.run(communicate())

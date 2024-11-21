from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad
import asyncio
import websockets


def load_or_generate_rsa_keys(private_key_file, public_key_file):
    try:
        with open(private_key_file, "rb") as f:
            private_key = RSA.import_key(f.read())
        print("Private key server berhasil dimuat.")
    except FileNotFoundError:
        private_key = RSA.generate(2048)
        with open(private_key_file, "wb") as f:
            f.write(private_key.export_key())
        print("Private key baru berhasil dibuat.")

    public_key = private_key.publickey()
    with open(public_key_file, "wb") as f:
        f.write(public_key.export_key())
    print("Public key server berhasil disimpan.")
    return private_key, public_key


server_private_key, server_public_key = load_or_generate_rsa_keys("server_private.pem", "server_public.pem")


async def handle_client(websocket):
    print("Client terhubung.")
    try:
        # Kirim public key ke client
        await websocket.send(server_public_key.export_key().decode())
        print("Kunci publik server dikirim ke client.")

        # Terima DES key terenkripsi
        encrypted_des_key = bytes.fromhex(await websocket.recv())
        rsa_cipher = PKCS1_OAEP.new(server_private_key)
        des_key = rsa_cipher.decrypt(encrypted_des_key)
        print(f"DES Key berhasil didekripsi: {des_key.hex()}")

        # Terima pesan terenkripsi
        encrypted_message = bytes.fromhex(await websocket.recv())
        des_cipher = DES.new(des_key, DES.MODE_ECB)
        decrypted_message = unpad(des_cipher.decrypt(encrypted_message), DES.block_size)
        print(f"Pesan dari Client: {decrypted_message.decode()}")

        # Kirim balasan
        reply = input("Masukkan balasan untuk Client: ").encode()
        encrypted_reply = des_cipher.encrypt(pad(reply, DES.block_size))
        await websocket.send(encrypted_reply.hex())
        print("Balasan terenkripsi berhasil dikirim ke client.")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")
    finally:
        print("Client terputus.")


async def main():
    async with websockets.serve(handle_client, "localhost", 8765):
        print("Server berjalan di ws://localhost:8765")
        await asyncio.Future()  # Menjaga server tetap berjalan


asyncio.run(main())

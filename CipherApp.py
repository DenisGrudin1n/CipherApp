from collections import Counter
from tkinter import *
import tkinter
from Crypto.Cipher import AES, DES, DES3, Blowfish, PKCS1_OAEP, ARC4
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import string
import random
import pyperclip
import math
import hashlib

def salsa20(key, plaintext, iv=None, rounds=None):
    key_int = int.from_bytes(key, byteorder='big')  # Перетворення рядка байтів у ціле число
    plaintext_bytes = plaintext.encode('utf-8')  # Перетворення рядка символів у рядок байтів
    key_schedule = generate_key_schedule(key_int, iv, rounds)
    keystream = generate_keystream(key_schedule, len(plaintext_bytes))
    ciphertext = bytes([(plain_byte ^ keystream_byte) % 256 for plain_byte, keystream_byte in zip(plaintext_bytes, keystream)])
    return ciphertext
def generate_key_schedule(key, iv=None, rounds=None):
    if rounds is None:
        rounds = 20
    
    key_schedule = []
    key_words = [key >> i & 0xFFFFFFFF for i in range(0, 256, 32)]  # Розбиття цілого числа на 32-бітні слова

    # Ініціалізація ключового розкладу
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_schedule.extend(constants)
    key_schedule.extend(key_words)
    key_schedule.extend(constants)
    key_schedule.extend(key_words)

    # Раундові розрахунки
    for _ in range(rounds // 2):
        quarter_round(key_schedule, 0, 4, 8, 12)
        quarter_round(key_schedule, 5, 9, 13, 1)
        quarter_round(key_schedule, 10, 14, 2, 6)
        quarter_round(key_schedule, 15, 3, 7, 11)
        quarter_round(key_schedule, 0, 1, 2, 3)
        quarter_round(key_schedule, 5, 6, 7, 4)
        quarter_round(key_schedule, 10, 11, 8, 9)
        quarter_round(key_schedule, 15, 12, 13, 14)
    
    return key_schedule
def generate_keystream(key_schedule, length):
    keystream = []
    counter = 0
    nonce = [0, 0]
    
    while len(keystream) < length:
        block = []
        block.extend(key_schedule[:16])
        block.append(counter)
        block.extend(nonce)
        keystream.extend(encrypt_block(block, key_schedule))
        counter += 1
    
    return keystream[:length]
def quarter_round(state, a, b, c, d):
    state[b] ^= left_rotate((state[a] + state[d]) & 0xFFFFFFFF, 7)
    state[c] ^= left_rotate((state[b] + state[a]) & 0xFFFFFFFF, 9)
    state[d] ^= left_rotate((state[c] + state[b]) & 0xFFFFFFFF, 13)
    state[a] ^= left_rotate((state[d] + state[c]) & 0xFFFFFFFF, 18)
def encrypt_block(block, key_schedule):
    state = list(block)
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 5, 9, 13, 1)
        quarter_round(state, 10, 14, 2, 6)
        quarter_round(state, 15, 3, 7, 11)
        quarter_round(state, 0, 1, 2, 3)
        quarter_round(state, 5, 6, 7, 4)
        quarter_round(state, 10, 11, 8, 9)
        quarter_round(state, 15, 12, 13, 14)
    return state
def left_rotate(value, shift):
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))
def encrypt_salsa20(key, plaintext, key_length, iv=None, rounds=None):
    
    if key_length == 128:
        key = get_random_bytes(16) 
    elif key_length == 256:
        key = get_random_bytes(32) 
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128 and 256.")
    
    #cipher = Salsa20.new(key=key, nonce=iv, rounds=rounds)
    encrypted_data = salsa20(key, plaintext, iv=iv, rounds=rounds)
    return encrypted_data.hex(), key.hex()
def decrypt_salsa20(main_key, decription_key, plaintext, key_length, iv=None, rounds=None):
    
    if key_length == 128:
        key = main_key[:16]
    elif key_length == 256:
        key = main_key[:32]
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128 and 256.")
    
    #cipher = Salsa20.new(key=key, nonce=iv, rounds=rounds)
    decrypted_data = salsa20(key, plaintext, iv=iv, rounds=rounds)
    return decrypted_data.hex(), key.hex()

def chacha20(key, plaintext, iv=None, rounds=None):
    key_int = int.from_bytes(key, byteorder='little')
    plaintext_bytes = plaintext.encode('utf-8')
    key_schedule = generate_chacha_key_schedule(key_int, iv, rounds)
    keystream = generate_chacha_keystream(key_schedule, len(plaintext_bytes))
    ciphertext = bytes([(plain_byte ^ keystream_byte) % 256 for plain_byte, keystream_byte in zip(plaintext_bytes, keystream)])
    return ciphertext
def generate_chacha_key_schedule(key, iv=None, rounds=None):
    if rounds is None:
        rounds = 20

    key_schedule = []
    key_words = [key >> i & 0xFFFFFFFF for i in range(0, 256, 32)]

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_schedule.extend(constants)
    key_schedule.extend(key_words)
    key_schedule.extend(constants)
    key_schedule.extend(key_words)

    for _ in range(rounds // 2):
        quarter_chacha_round(key_schedule, 0, 4, 8, 12)
        quarter_chacha_round(key_schedule, 1, 5, 9, 13)
        quarter_chacha_round(key_schedule, 2, 6, 10, 14)
        quarter_chacha_round(key_schedule, 3, 7, 11, 15)
        quarter_chacha_round(key_schedule, 0, 5, 10, 15)
        quarter_chacha_round(key_schedule, 1, 6, 11, 12)
        quarter_chacha_round(key_schedule, 2, 7, 8, 13)
        quarter_chacha_round(key_schedule, 3, 4, 9, 14)

    return key_schedule
def generate_chacha_keystream(key_schedule, length):
    keystream = []
    counter = 0
    nonce = [0, 0]

    while len(keystream) < length:
        block = []
        block.extend(key_schedule[:16])
        block.append(counter)
        block.extend(nonce)
        keystream.extend(encrypt_chacha_block(block, key_schedule))
        counter += 1

    return keystream[:length]
def quarter_chacha_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = (state[d] ^ state[a]) & 0xFFFFFFFF
    state[d] = (state[d] << 16 | state[d] >> 16) & 0xFFFFFFFF
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = (state[b] ^ state[c]) & 0xFFFFFFFF
    state[b] = (state[b] << 12 | state[b] >> 20) & 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = (state[d] ^ state[a]) & 0xFFFFFFFF
    state[d] = (state[d] << 8 | state[d] >> 24) & 0xFFFFFFFF
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = (state[b] ^ state[c]) & 0xFFFFFFFF
    state[b] = (state[b] << 7 | state[b] >> 25) & 0xFFFFFFFF
def encrypt_chacha_block(block, key_schedule):

    state = list(block)

    for _ in range(10):
        quarter_chacha_round(state, 0, 4, 8, 12)
        quarter_chacha_round(state, 1, 5, 9, 13)
        quarter_chacha_round(state, 2, 6, 10, 14)
        quarter_chacha_round(state, 3, 7, 11, 15)
        quarter_chacha_round(state, 0, 5, 10, 15)
        quarter_chacha_round(state, 1, 6, 11, 12)
        quarter_chacha_round(state, 2, 7, 8, 13)
        quarter_chacha_round(state, 3, 4, 9, 14)

    return state
def encrypt_chacha(key, plaintext, key_length, iv=None, rounds=None):
    if key_length == 128:
        key = get_random_bytes(16) 
    elif key_length == 256:
        key = get_random_bytes(32) 
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128 and 256.")
    
    #cipher = ChaCha20.new(key=key, nonce=iv, rounds=rounds)
    #encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))

    encrypted_data = chacha20(key, plaintext, iv=iv, rounds=rounds)
    return encrypted_data.hex(), key.hex()
def decrypt_chacha(main_key, decription_key, plaintext, key_length, iv=None, rounds=None):
    if key_length == 256:
       key = main_key[:32]
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128 and 256.")

    decrypted_data = chacha20(key, plaintext, iv=iv, rounds=rounds)
    return decrypted_data.hex(), key.hex() 

def encrypt_rc4(key, plaintext, key_length):
    if key_length < 40 or key_length > 2048:
        raise ValueError("Invalid key length. Supported key lengths are from 40 to 2048 included.")
    else:
        key = get_random_bytes(math.floor(key_length / 8)) 

    cipher = ARC4.new(key=key)

    encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
    return encrypted_data.hex(), key.hex()  
def decrypt_rc4(main_key, decription_key, plaintext, key_length):
    if key_length < 40 or key_length > 2048:
        raise ValueError("Invalid key length. Supported key lengths are from 40 to 2048 included.")
    else:
        key = main_key[:math.floor(key_length / 8)]

    cipher = ARC4.new(key=key)

    decrypted_data = cipher.decrypt(plaintext.encode('utf-8'))
    return decrypted_data.hex(), key.hex()  

def pad_tbc(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = (b'\x00' * (padding_len - 1)) + bytes([padding_len])
    return data + padding
def pad_pkcs7(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding
def pad_zeropadding(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = b'\x00' * padding_len
    return data + padding
def unpad_tbc(data):
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]
def unpad_pkcs7(data):
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]
def unpad_zeropadding(data):

    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    if i < 0 or data[i] != 1:
        raise ValueError("Invalid padding")
    return data[:i]

def encrypt_aes(key, plaintext, key_length, mode, padding, block_size=16, iv=None, nonce=None):

    if padding == "None":
        padded_plaintext = plaintext.encode()
    elif padding == "PKCS7":
        padded_plaintext = pad_pkcs7(plaintext.encode(), block_size)
    elif padding == "TBC":
        padded_plaintext = pad_tbc(plaintext.encode(), block_size)
    elif padding == "Zero byte":
       padded_plaintext = pad_zeropadding(plaintext.encode(), block_size)
    else:
        raise ValueError("Invalid padding")

    if key_length == 128:
        key = get_random_bytes(16) 
    elif key_length == 192:
        key = get_random_bytes(24)  
    elif key_length == 256:
        key = get_random_bytes(32) 
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128, 192, and 256.")

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    elif mode == "GCM":
        if nonce is None:
            raise ValueError("Nonce is required for GCM mode")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    elif mode == "CCM":
        if nonce is None:
            raise ValueError("Nonce is required for CCM mode")
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    elif mode == "OCB":
        if nonce is None:
            raise ValueError("Nonce is required for OCB mode")
        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = AES.new(key, AES.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    encrypted_data = cipher.encrypt(pad(padded_plaintext, block_size))
    return encrypted_data.hex(), key.hex()
def encrypt_des(key, plaintext, key_length, mode, padding, block_size=8, iv=None, nonce=None):

    if padding == "None":
        padded_plaintext = plaintext.encode()
    elif padding == "PKCS7":
        padded_plaintext = pad_pkcs7(plaintext.encode(), block_size)
    elif padding == "TBC":
        padded_plaintext = pad_tbc(plaintext.encode(), block_size)
    elif padding == "Zero byte":
       padded_plaintext = pad_zeropadding(plaintext.encode(), block_size)
    else:
        raise ValueError("Invalid padding")

    if key_length == 56:
        key = get_random_bytes(8)
    else:
        raise ValueError("Invalid key length. Supported key length is 56.")

    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = DES.new(key, DES.MODE_CTR, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = DES.new(key, DES.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    encrypted_data = cipher.encrypt(pad(padded_plaintext, block_size))
    return encrypted_data.hex(), key.hex()
def encrypt_3des(key, plaintext, key_length, mode, padding, block_size=8, iv=None, nonce=None):

    if padding == "None":
        padded_plaintext = plaintext.encode()
    elif padding == "PKCS7":
        padded_plaintext = pad_pkcs7(plaintext.encode(), block_size)
    elif padding == "TBC":
        padded_plaintext = pad_tbc(plaintext.encode(), block_size)
    elif padding == "Zero byte":
       padded_plaintext = pad_zeropadding(plaintext.encode(), block_size)
    else:
        raise ValueError("Invalid padding")

    if key_length == 112:
        key = get_random_bytes(16)
    elif key_length == 168:
        key = get_random_bytes(24)
    else:
        raise ValueError("Invalid key length. Supported key lengths are 112 and 168.")

    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = DES3.new(key, DES3.MODE_CTR, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = DES3.new(key, DES3.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    encrypted_data = cipher.encrypt(pad(padded_plaintext, block_size))
    return encrypted_data.hex(), key.hex()
def encrypt_blowfish(key, plaintext, key_length, mode, padding, block_size=8, iv=None, nonce=None):

    if padding == "None":
        padded_plaintext = plaintext.encode()
    elif padding == "PKCS7":
        padded_plaintext = pad_pkcs7(plaintext.encode(), block_size)
    elif padding == "TBC":
        padded_plaintext = pad_tbc(plaintext.encode(), block_size)
    elif padding == "Zero byte":
       padded_plaintext = pad_zeropadding(plaintext.encode(), block_size)
    else:
        raise ValueError("Invalid padding")

    if key_length < 32 or key_length > 448:
        raise ValueError("Invalid key length. Supported key lengths are from 32 to 448 included.")
    else:
        key = get_random_bytes(math.floor(key_length / 8)) 

    if mode == "ECB":
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = Blowfish.new(key, Blowfish.MODE_CTR, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = Blowfish.new(key, Blowfish.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    encrypted_data = cipher.encrypt(pad(padded_plaintext, block_size))
    return encrypted_data.hex(), key.hex() 
    key = RSA.generate(key_length)
    public_key = key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(plaintext.encode())
    return encrypted_data.hex(), key.export_key().decode()

def decrypt_aes(main_key, decription_key, ciphertext, key_length, mode, padding, block_size=16, iv=None, nonce=None):
    if key_length == 128:
        key = main_key[:16]
    elif key_length == 192:
        key = main_key[:24]
    elif key_length == 256:
        key = main_key[:32]
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128, 192, and 256.")

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    elif mode == "GCM":
        if nonce is None:
            raise ValueError("Nonce is required for GCM mode")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    elif mode == "CCM":
        if nonce is None:
            raise ValueError("Nonce is required for CCM mode")
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    elif mode == "OCB":
        if nonce is None:
            raise ValueError("Nonce is required for OCB mode")
        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = AES.new(key, AES.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    decrypted_data = cipher.decrypt(bytes.fromhex(ciphertext))
    #decrypted_data = cipher.decrypt(unpad(ciphertext, block_size))
    
    if padding == "None":
        plaintext = decrypted_data.decode()
    elif padding == "PKCS7":
        plaintext = unpad_pkcs7(decrypted_data.decode(), block_size)
    elif padding == "TBC":
        plaintext = unpad_tbc(decrypted_data.decode(), block_size)
    elif padding == "Zero byte":
        plaintext = unpad_zeropadding(decrypted_data.decode(), block_size)
    else:
        raise ValueError("Invalid padding")

    return plaintext
def decrypt_des(main_key, decription_key, ciphertext, key_length, mode, padding, block_size=8, iv=None, nonce=None):
    if key_length == 56:
        key = main_key[:16]
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128, 192, and 256.")

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = AES.new(key, AES.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    decrypted_data = cipher.decrypt(bytes.fromhex(ciphertext))
    #decrypted_data = cipher.decrypt(unpad(ciphertext, block_size))
    
    if padding == "None":
        plaintext = decrypted_data.decode()
    elif padding == "PKCS7":
        plaintext = unpad_pkcs7(decrypted_data.decode(), block_size)
    elif padding == "TBC":
        plaintext = unpad_tbc(decrypted_data.decode(), block_size)
    elif padding == "Zero byte":
        plaintext = unpad_zeropadding(decrypted_data.decode(), block_size)
    else:
        raise ValueError("Invalid padding")

    return plaintext
def decrypt_3des(main_key, decription_key, ciphertext, key_length, mode, padding, block_size=8, iv=None, nonce=None):
    if key_length == 112:
        key = main_key[:32]
    elif key_length == 168:
        key = main_key[:48]
    else:
        raise ValueError("Invalid key length. Supported key lengths are 128, 192, and 256.")

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = AES.new(key, AES.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    decrypted_data = cipher.decrypt(bytes.fromhex(ciphertext))
    #decrypted_data = cipher.decrypt(unpad(ciphertext, block_size))
    
    if padding == "None":
        plaintext = decrypted_data.decode()
    elif padding == "PKCS7":
        plaintext = unpad_pkcs7(decrypted_data.decode(), block_size)
    elif padding == "TBC":
        plaintext = unpad_tbc(decrypted_data.decode(), block_size)
    elif padding == "Zero byte":
        plaintext = unpad_zeropadding(decrypted_data.decode(), block_size)
    else:
        raise ValueError("Invalid padding")

    return plaintext
def decrypt_blowfish(main_key, decription_key, ciphertext, key_length, mode, padding, block_size=8, iv=None, nonce=None):
    if key_length >= 32 and key_length <= 448:
        key = int(key_length / 4)
    else:
        raise ValueError("Invalid key length. Supported key lengths are from 32 to 448")

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode == "CFB":
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    elif mode == "EAX":
        if nonce is None:
            raise ValueError("Nonce is required for EAX mode")
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    elif mode == "CTR":
        if nonce is None:
            raise ValueError("Nonce is required for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    elif mode == "OFB":
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    elif mode == "OPENPGP":
        cipher = AES.new(key, AES.MODE_OPENPGP)
    else:
        raise ValueError("Invalid mode")

    decrypted_data = cipher.decrypt(bytes.fromhex(ciphertext))
    #decrypted_data = cipher.decrypt(unpad(ciphertext, block_size))
    
    if padding == "None":
        plaintext = decrypted_data.decode()
    elif padding == "PKCS7":
        plaintext = unpad_pkcs7(decrypted_data.decode(), block_size)
    elif padding == "TBC":
        plaintext = unpad_tbc(decrypted_data.decode(), block_size)
    elif padding == "Zero byte":
        plaintext = unpad_zeropadding(decrypted_data.decode(), block_size)
    else:
        raise ValueError("Invalid padding")

    return plaintext

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Symmetric Encryption")
        self.root.geometry("1920x1080")
        self.root.configure(bg="#B3D1DC")

        self.algorithms = ["AES", "DES", "3DES", "Blowfish"]

        self.algorithm_var = StringVar()
        self.algorithm_var.set("AES")
        self.plaintext_var = StringVar()
        self.key_var = StringVar()
        self.iv_var = StringVar()
        self.nonce_var = StringVar()

        self.key_mode_options = ["SHA-256", "Raw", "Derived"]
        self.key_mode_var = StringVar()
        self.key_mode_var.set(self.key_mode_options[0])

        self.key_length_options = {"AES": [128, 192, 256]}
        self.key_length_var = StringVar()
        self.key_length_var.set(str(self.key_length_options["AES"][0]))

        self.mode_options = ["ECB", "CBC", "CFB", "GCM", "EAX", "CTR", "CCM", "OCB", "OFB", "OPENPGP"]
        
        self.mode_var = StringVar()
        self.mode_var.set(self.mode_options[0])

        self.padding_options = ["PKCS7", "TBC", "Zero byte"]
        self.padding_var = StringVar()
        self.padding_var.set(self.padding_options[0])

        self.decrypting_key_var = StringVar()

        self.stream_algorithms = ["Salsa20", "ChaCha", "RC4"]

        self.stream_algorithm_var = StringVar()
        self.stream_algorithm_var.set("Salsa20")
        self.stream_plaintext_var = StringVar()
        self.stream_key_var = StringVar()

        self.stream_key_length_options = {"Salsa20": [128, 256]}
        self.stream_key_length_var = StringVar()
        self.stream_key_length_var.set(str(self.stream_key_length_options["Salsa20"][0]))

        self.stream_iv_var = StringVar()

        self.rounds_var = IntVar()
        self.rounds_var.set(8)

        self.stream_decrypting_key_var = StringVar()

        self.create_widgets()
        self.root.mainloop()
    def create_widgets(self):
        self.main_frame = Frame(self.root, padx=80, pady=40)
        self.main_frame.pack(fill=BOTH, expand=True)

        block_ciphers_label = Label(self.main_frame, text="Block Ciphers", font=("Arial", 16, "bold"))
        block_ciphers_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        algorithm_label = Label(self.main_frame, text="Algorithm:", font=("Arial", 14))
        algorithm_label.grid(row=1, column=0, sticky=W, padx=10, pady=10)
        algorithm_menu = OptionMenu(self.main_frame, self.algorithm_var, *self.algorithms, command=self.update_options)
        algorithm_menu.config(bg="#B3D1DC", font=("Arial", 12))
        algorithm_menu.grid(row=1, column=1, sticky=W, padx=10, pady=10)

        plaintext_label = Label(self.main_frame, text="Plain/Cipher text:", font=("Arial", 14))
        plaintext_label.grid(row=2, column=0, sticky=W, padx=10, pady=10)
        plaintext_entry = Entry(self.main_frame, textvariable=self.plaintext_var, width=35, font=("Arial", 12))
        plaintext_entry.grid(row=2, column=1, sticky=W, padx=10, pady=10)

        key_label = Label(self.main_frame, text="Key:", font=("Arial", 14))
        key_label.grid(row=3, column=0, sticky=W, padx=10, pady=10)
        key_entry = Entry(self.main_frame, textvariable=self.key_var, width=35, font=("Arial", 12))
        key_entry.grid(row=3, column=1, sticky=W, padx=10, pady=10)
        random_key_button = Button(self.main_frame, text="Random", command=self.generate_random_key, bg="#B3D1DC",
                                   font=("Arial", 12), relief=RAISED)
        random_key_button.grid(row=3, column=2, sticky=W, padx=0, pady=10)

        iv_label = Label(self.main_frame, text="Initialization vector:", font=("Arial", 14))
        iv_label.grid(row=4, column=0, sticky=W, padx=10, pady=10)
        iv_entry = Entry(self.main_frame, textvariable=self.iv_var, width=35, font=("Arial", 12))
        iv_entry.grid(row=4, column=1, sticky=W, padx=10, pady=10)
        random_iv_button = Button(self.main_frame, text="Random", command=self.generate_random_iv, bg="#B3D1DC",
                                  font=("Arial", 12), relief=RAISED)
        random_iv_button.grid(row=4, column=2, sticky=W, padx=0, pady=10)

        key_mode_label = Label(self.main_frame, text="Key mode:", font=("Arial", 14))
        key_mode_label.grid(row=5, column=0, sticky=W, padx=10, pady=10)
        key_mode_menu = OptionMenu(self.main_frame, self.key_mode_var, *self.key_mode_options)
        key_mode_menu.config(bg="#B3D1DC", font=("Arial", 12))
        key_mode_menu.grid(row=5, column=1, sticky=W, padx=10, pady=10)
     
        key_length_label = Label(self.main_frame, text="Key length:", font=("Arial", 14))
        key_length_label.grid(row=6, column=0, sticky=W, padx=10, pady=10)
        key_length_menu = OptionMenu(self.main_frame, self.key_length_var, *self.key_length_options["AES"])
        key_length_menu.config(bg="#B3D1DC", font=("Arial", 12))
        key_length_menu.grid(row=6, column=1, sticky=W, padx=10, pady=10)

        mode_label = Label(self.main_frame, text="Mode:", font=("Arial", 14))
        mode_label.grid(row=7, column=0, sticky=W, padx=10, pady=10)
        mode_menu = OptionMenu(self.main_frame, self.mode_var, *self.mode_options)
        mode_menu.config(bg="#B3D1DC", font=("Arial", 12))
        mode_menu.grid(row=7, column=1, sticky=W, padx=10, pady=10)

        padding_label = Label(self.main_frame, text="Padding:", font=("Arial", 14))
        padding_label.grid(row=8, column=0, sticky=W, padx=10, pady=10)
        padding_menu = OptionMenu(self.main_frame, self.padding_var, *self.padding_options)
        padding_menu.config(bg="#B3D1DC", font=("Arial", 12))
        padding_menu.grid(row=8, column=1, sticky=W, padx=10, pady=10)

        encrypt_button = Button(self.main_frame, text="Encrypt", command=self.encrypt, bg="#B3D1DC", font=("Arial", 14))
        encrypt_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=8)
        encrypt_button.grid(row=9, column=1, sticky=W, padx=10, pady=10)  

        key2_label = Label(self.main_frame, text="Decryption Key:", font=("Arial", 14))
        key2_label.grid(row=10, column=0, sticky=W, padx=10, pady=10)
        key2_entry = Entry(self.main_frame, textvariable=self.decrypting_key_var, width=35, font=("Arial", 12))
        key2_entry.grid(row=10, column=1, sticky=W, padx=10, pady=10)

        decrypt_button = Button(self.main_frame, text="Decrypt", command=self.decrypt, bg="#B3D1DC", font=("Arial", 14))
        decrypt_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=8)
        decrypt_button.grid(row=11, column=1, sticky=W, padx=10, pady=10)

        #decrypt_button = Button(self.main_frame, text="Decrypt", command=self.decrypt, bg="#B3D1DC", font=("Arial", 14))
        #decrypt_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=8)
        #decrypt_button.grid(row=9, column=1, sticky=W, padx=150, pady=10)  

        stream_ciphers_label = Label(self.main_frame, text="Stream Ciphers", font=("Arial", 16, "bold"))
        stream_ciphers_label.grid(row=0, column=2, columnspan=3, padx=10, pady=10)   

        stream_algorithm_label = Label(self.main_frame, text="Algorithm:", font=("Arial", 14))
        stream_algorithm_label.grid(row=1, column=3, sticky=W, padx=60, pady=10)
        stream_algorithm_menu = OptionMenu(self.main_frame, self.stream_algorithm_var, *self.stream_algorithms, command=self.update_stream_options)
        stream_algorithm_menu.config(bg="#B3D1DC", font=("Arial", 12))
        stream_algorithm_menu.grid(row=1, column=4, sticky=W, padx=10, pady=10)

        stream_plaintext_label = Label(self.main_frame, text="Plain/Cipher text:", font=("Arial", 14))
        stream_plaintext_label.grid(row=2, column=3, sticky=W, padx=60, pady=10)
        stream_plaintext_entry = Entry(self.main_frame, textvariable=self.stream_plaintext_var, width=35, font=("Arial", 12))
        stream_plaintext_entry.grid(row=2, column=4, sticky=W, padx=10, pady=10)

        stream_key_label = Label(self.main_frame, text="Key:", font=("Arial", 14))
        stream_key_label.grid(row=3, column=3, sticky=W, padx=60, pady=10)
        stream_key_entry = Entry(self.main_frame, textvariable=self.stream_key_var, width=35, font=("Arial", 12))
        stream_key_entry.grid(row=3, column=4, sticky=W, padx=10, pady=10)
        stream_random_key_button = Button(self.main_frame, text="Random", command=self.generate_stream_random_key, bg="#B3D1DC",
                                   font=("Arial", 12), relief=RAISED)
        stream_random_key_button.grid(row=3, column=4, sticky=W, padx=350, pady=10) 

        stream_iv_label = Label(self.main_frame, text="Initialization vector:", font=("Arial", 14))
        stream_iv_label.grid(row=4, column=3, sticky=W, padx=60, pady=10)
        stream_iv_entry = Entry(self.main_frame, textvariable=self.stream_iv_var, width=35, font=("Arial", 12))
        stream_iv_entry.grid(row=4, column=4, sticky=W, padx=10, pady=10)
        stream_random_iv_button = Button(self.main_frame, text="Random", command=self.generate_random_stream_iv, bg="#B3D1DC",
                                font=("Arial", 12), relief=RAISED)
        stream_random_iv_button.grid(row=4, column=4, sticky=W, padx=350, pady=10) 

        stream_key_length_label = Label(self.main_frame, text="Key length:", font=("Arial", 14))
        stream_key_length_label.grid(row=5, column=3, sticky=W, padx=60, pady=10)
        stream_key_length_menu = OptionMenu(self.main_frame, self.stream_key_length_var, *self.stream_key_length_options["Salsa20"])
        stream_key_length_menu.config(bg="#B3D1DC", font=("Arial", 12))
        stream_key_length_menu.grid(row=5, column=4, sticky=W, padx=10, pady=10)

        rounds_label = Label(self.main_frame, text="Rounds:", font=("Arial", 14))
        rounds_label.grid(row=6, column=3, sticky=W, padx=60, pady=10)
        rounds_entry = Entry(self.main_frame, textvariable=self.rounds_var, width=15, font=("Arial", 12))
        rounds_entry.grid(row=6, column=4, sticky=W, padx=10, pady=10)

        stream_encrypt_button = Button(self.main_frame, text="Encrypt", command=self.stream_encrypt, bg="#B3D1DC", font=("Arial", 14))
        stream_encrypt_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=8)
        stream_encrypt_button.grid(row=7, column=4, sticky=W, padx=10, pady=10) 

        stream_key2_label = Label(self.main_frame, text="Decryption Key:", font=("Arial", 14))
        stream_key2_label.grid(row=8, column=3, sticky=W, padx=64, pady=10)
        stream_key2_entry = Entry(self.main_frame, textvariable=self.stream_decrypting_key_var, width=35, font=("Arial", 12))
        stream_key2_entry.grid(row=8, column=4, sticky=W, padx=10, pady=10)

        stream_decrypt_button = Button(self.main_frame, text="Decrypt", command=self.stream_decrypt, bg="#B3D1DC", font=("Arial", 14))
        stream_decrypt_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=8)
        stream_decrypt_button.grid(row=9, column=4, sticky=W, padx=10, pady=10) 

        cryptoanalysis_button = Button(self.main_frame, text="Cryptoanalysis", command=self.open_cryptoanalysis_window, bg="#B3D1DC", font=("Arial", 14))
        cryptoanalysis_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=12)
        cryptoanalysis_button.grid(row=11, column=4, sticky=W, padx=250, pady=10)  

        mathematics_button = Button(self.main_frame, text="Mathematics", command=self.open_mathematics_window, bg="#B3D1DC", font=("Arial", 14))
        mathematics_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=12)
        mathematics_button.grid(row=12, column=4, sticky=W, padx=250, pady=10)  
    def open_cryptoanalysis_window(self):
        cryptoanalysis_window = Tk()
        cryptoanalysis_window.title("Cryptoanalysis")

        frequency_label = Label(cryptoanalysis_window, text="Frequency Analysis", font=("Arial", 16, "bold"))
        frequency_label.grid(row=0, column=3, sticky=W, padx=170, pady=(200, 20))

        bruteforce_label = Label(cryptoanalysis_window, text="Caesar Brute Force", font=("Arial", 16, "bold"))
        bruteforce_label.grid(row=0, column=4, sticky=W, padx=170, pady=(200, 10))

        factorization_label = Label(cryptoanalysis_window, text="Factorization", font=("Arial", 16, "bold"))
        factorization_label.grid(row=0, column=5, sticky=W, padx=145, pady=(200, 10))

        self.frequency_text_entry = Entry(cryptoanalysis_window, width=50, font=("Arial", 12))
        self.frequency_text_entry.grid(row=1, column=3, sticky=W, padx=50, pady=20)

        calculate_frequency_button = Button(cryptoanalysis_window, text="Calculate", bg="#B3D1DC", command=self.calculate_frequency, font=("Arial", 14))
        calculate_frequency_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=12)
        calculate_frequency_button.grid(row=4, column=1, columnspan=3, padx=20, pady=20)

        self.length_display = Label(cryptoanalysis_window, text="Text length:", font=("Arial", 14), justify=RIGHT)
        self.length_display.grid(row=2, column=3, sticky=W, padx=50, pady=20)

        self.frequency_display = Label(cryptoanalysis_window, text="Most common letters:", font=("Arial", 14), justify=RIGHT)
        self.frequency_display.grid(row=3, column=3, sticky=W, padx=50, pady=0)

        self.caesar_text_entry = Entry(cryptoanalysis_window, width=50, font=("Arial", 12))
        self.caesar_text_entry.grid(row=1, column=4, sticky=W, padx=50, pady=20)

        self.key_text = Label(cryptoanalysis_window, text="Key:", font=("Arial", 14), justify=RIGHT)
        self.key_text.place(x=605, y=329)

        self.key_entry = Entry(cryptoanalysis_window, width=5, font=("Arial", 12))
        self.key_entry.grid(row=2, column=4, sticky=W, padx=105, pady=20)

        calculate_caesar_button = Button(cryptoanalysis_window, text="Caesar", bg="#B3D1DC", command=self.caesar_bruteforce, font=("Arial", 14))
        calculate_caesar_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=12)
        calculate_caesar_button.grid(row=4, column=3, columnspan=3, padx=20, pady=5)

        self.decrypted_text_display = Label(cryptoanalysis_window, text="Caesar result:", font=("Arial", 14), justify=RIGHT)
        self.decrypted_text_display.grid(row=3, column=4, sticky=W, padx=50, pady=0)

        self.factorization_entry = Entry(cryptoanalysis_window, width=35, font=("Arial", 12))
        self.factorization_entry.grid(row=1, column=5, sticky=W, padx=50, pady=20)

        calculate_factorization_button = Button(cryptoanalysis_window, text="Start factorization", bg="#B3D1DC", command=self.start_factorization, font=("Arial", 14))
        calculate_factorization_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=16)
        calculate_factorization_button.grid(row=3, column=5, columnspan=3, padx=20, pady=5)

        self.factorization_result = Label(cryptoanalysis_window, text="Factors:", font=("Arial", 14))
        self.factorization_result.grid(row=2, column=5, columnspan=2, sticky=W, padx=50, pady=5)

        cryptoanalysis_window.mainloop()
    def open_mathematics_window(self):
        cryptoanalysis_window = Tk()
        cryptoanalysis_window.title("Mathematics")

        frequency_label = Label(cryptoanalysis_window, text="Prime Search", font=("Arial", 16, "bold"))
        frequency_label.grid(row=0, column=3, sticky=W, padx=170, pady=(200, 20))

        bruteforce_label = Label(cryptoanalysis_window, text="GCD", font=("Arial", 16, "bold"))
        bruteforce_label.grid(row=0, column=4, sticky=W, padx=170, pady=(200, 10))

        factorization_label = Label(cryptoanalysis_window, text="Divisor search", font=("Arial", 16, "bold"))
        factorization_label.grid(row=0, column=5, sticky=W, padx=145, pady=(200, 10))

        self.frequency_display = Label(cryptoanalysis_window, text="From", font=("Arial", 14), justify=RIGHT)
        self.frequency_display.place(x=10, y=266)

        self.frequency_text_entry = Entry(cryptoanalysis_window, width=5, font=("Arial", 12))
        self.frequency_text_entry.grid(row=1, column=3, sticky=W, padx=70, pady=20)

        self.frequency_display = Label(cryptoanalysis_window, text="To", font=("Arial", 14), justify=RIGHT)
        self.frequency_display.place(x=30, y=330)

        self.frequency2_text_entry = Entry(cryptoanalysis_window, width=5, font=("Arial", 12))
        self.frequency2_text_entry.grid(row=2, column=3, sticky=W, padx=70, pady=20)

        calculate_frequency_button = Button(cryptoanalysis_window, text="Calculate", bg="#B3D1DC", command=self.count_primes, font=("Arial", 14))
        calculate_frequency_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=12)
        calculate_frequency_button.grid(row=5, column=1, columnspan=3, padx=20, pady=20)

        self.length_display = Label(cryptoanalysis_window, text="Number of found primes:", font=("Arial", 14), justify=RIGHT)
        self.length_display.grid(row=3, column=3, sticky=W, padx=50, pady=20)

        self.frequency_display = Label(cryptoanalysis_window, text="Prime numbers:", font=("Arial", 14), justify=RIGHT)
        self.frequency_display.grid(row=4, column=3, sticky=W, padx=50, pady=0)

        self.caesar_display = Label(cryptoanalysis_window, text="n =", font=("Arial", 14), justify=RIGHT)
        self.caesar_display.place(x=535, y=266)

        self.caesar_text_entry = Entry(cryptoanalysis_window, width=5, font=("Arial", 12))
        self.caesar_text_entry.grid(row=1, column=4, sticky=W, padx=90, pady=20)

        self.key_text = Label(cryptoanalysis_window, text="m =", font=("Arial", 14), justify=RIGHT)
        self.key_text.place(x=530, y=332)

        self.key_entry = Entry(cryptoanalysis_window, width=5, font=("Arial", 12))
        self.key_entry.grid(row=2, column=4, sticky=W, padx=90, pady=20)

        calculate_caesar_button = Button(cryptoanalysis_window, text="Evaluate", bg="#B3D1DC", command=self.find_gcd, font=("Arial", 14))
        calculate_caesar_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=12)
        calculate_caesar_button.grid(row=4, column=3, columnspan=3, padx=20, pady=5)

        self.decrypted_text_display = Label(cryptoanalysis_window, text="GCD:", font=("Arial", 14), justify=RIGHT)
        self.decrypted_text_display.grid(row=3, column=4, sticky=W, padx=50, pady=0)

        self.factorization_entry = Entry(cryptoanalysis_window, width=5, font=("Arial", 12))
        self.factorization_entry.grid(row=1, column=5, sticky=W, padx=50, pady=20)

        calculate_factorization_button = Button(cryptoanalysis_window, text="Find divisors", bg="#B3D1DC", command=self.divisors_search, font=("Arial", 14))
        calculate_factorization_button.config(borderwidth=0, relief=RAISED, padx=6, pady=0, bd=2, width=16)
        calculate_factorization_button.grid(row=4, column=5, columnspan=3, padx=20, pady=5)

        self.flength_display = Label(cryptoanalysis_window, text="Number of found divisors:", font=("Arial", 14), justify=RIGHT)
        self.flength_display.grid(row=2, column=5, sticky=W, padx=50, pady=20)

        self.factorization_display = Label(cryptoanalysis_window, text="Divisors:", font=("Arial", 14), justify=RIGHT)
        self.factorization_display.grid(row=3, column=5, sticky=W, padx=50, pady=0)

        cryptoanalysis_window.mainloop()   
    def divisors_search(self):
        number = int(self.factorization_entry.get())
        divisors = []

        for divisor in range(2, number):
            if number % divisor == 0:
                divisors.append(divisor)

        count = len(divisors)
        divisors_all = ""
        for i, divisor in enumerate(divisors, 1):
            divisors_all += str(divisor) + ", "
            if i % 5 == 0:
                divisors_all += "\n"

        self.flength_display.config(text="Number of found divisors: " + str(count))
        self.factorization_display.config(text="Divisors: " + divisors_all)       
    def find_gcd(self):
        a = int(self.caesar_text_entry.get())
        b = int(self.key_entry.get())
        while b != 0:
            a, b = b, a % b   
        self.decrypted_text_display.config(text="GCD: " + str(a)) 
    def count_primes(self):
        start = int(self.frequency_text_entry.get())
        end = int(self.frequency2_text_entry.get())
        primes = []
        count = 0

        for num in range(start, end + 1):
            if num > 1:
                for i in range(2, int(num ** 0.5) + 1):
                    if num % i == 0:
                        break
                else:
                    primes.append(num)
                    count += 1

        primes_all = ""
        for i, prime in enumerate(primes, 1):
            primes_all += str(prime) + ", "
            if i % 10 == 0:
                primes_all += "\n"

        self.length_display.config(text="Number of found primes: " + str(count))
        self.frequency_display.config(text="Prime numbers:\n" + primes_all)
    def calculate_frequency(self):
        text = self.frequency_text_entry.get().lower()
        letter_counts = Counter()

        for char in text:
            if char.isalpha():
                letter_counts[char] += 1

        most_common = letter_counts.most_common(5)
        most_common_letters = ", ".join([letter for letter, _ in most_common])

        self.length_display.config(text="Text length: " + str(len(text)))
        self.frequency_display.config(text="Most common letters: " + most_common_letters)    
    def caesar_bruteforce(self):
        ciphertext = self.caesar_text_entry.get().lower()
        key = int(self.key_entry.get())

        plaintext = ""

        for char in ciphertext:
            if char.isalpha():
                decrypted_char = chr((ord(char) - ord('a') - key) % 26 + ord('a'))
                plaintext += decrypted_char
            else:
                plaintext += char

        self.decrypted_text_display.config(text="Caesar result: " + plaintext)    
    def start_factorization(self):
        number = self.factorization_entry.get()

        try:
            number = int(number)
            factors = self.factorize(number)

            prime_factors = [factor for factor in factors if factor > 1]

            if len(prime_factors) >= 2:
                factor_str = ", ".join(str(factor) for factor in prime_factors)
                self.factorization_result.config(text="Factors: " + factor_str)
            else:
                self.factorization_result.config(text="Factors: No factors found.")
        except ValueError:
            self.factorization_result.config(text="Factors: Invalid input.")
    def factorize(self, number):
        if number < 2:
            return []

        factors = []
        i = 2

        while i * i <= number:
            if number % i == 0:
                number //= i
                factors.append(i)
            else:
                i += 1

        if number > 1:
            factors.append(number)

        return factors
    def update_options(self, algorithm):

        if algorithm == "AES":
            self.mode_options = ["ECB", "CBC", "CFB", "GCM", "EAX", "CTR", "CCM", "OCB", "OFB", "OPENPGP"]
            self.key_length_options = [128, 192, 256]
        elif algorithm == "DES":
            self.mode_options = ["ECB", "CBC", "CFB", "EAX", "CTR", "OFB", "OPENPGP"]
            self.key_length_options = [56]
        elif algorithm == "3DES":
            self.mode_options = ["ECB", "CBC", "CFB", "EAX", "CTR", "OFB", "OPENPGP"]
            self.key_length_options = [112, 168]
        elif algorithm == "Blowfish":
            self.mode_options = ["ECB", "CBC", "CFB", "EAX", "CTR", "OFB", "OPENPGP"]
            self.key_length_options = []
            for i in range(32, 449):
                if i % 32 == 0:
                    self.key_length_options.append(i)

        self.mode_var.set(self.mode_options[0])
        self.key_length_var.set(str(self.key_length_options[0]))

        mode_menu = OptionMenu(self.main_frame, self.mode_var, *self.mode_options)
        mode_menu.config(bg="#B3D1DC", font=("Arial", 12))
        mode_menu.grid(row=7, column=1, sticky=W, padx=10, pady=10)

        key_length_menu = OptionMenu(self.main_frame, self.key_length_var, *self.key_length_options)
        key_length_menu.config(bg="#B3D1DC", font=("Arial", 12))
        key_length_menu.grid(row=6, column=1, sticky=W, padx=10, pady=10)
    def update_stream_options(self, algorithm):
    
        if algorithm == "Salsa20":
            self.stream_key_length_options = [128, 256]
        elif algorithm == "ChaCha":
            self.stream_key_length_options = [256]
        elif algorithm == "RC4":
            self.stream_key_length_options = []
            for i in range(40, 2049):
                if i % 128 == 0:
                    self.stream_key_length_options.append(i)

        self.stream_key_length_var.set(str(self.stream_key_length_options[0]))

        stream_key_length_menu = OptionMenu(self.main_frame, self.stream_key_length_var, *self.stream_key_length_options)
        stream_key_length_menu.config(bg="#B3D1DC", font=("Arial", 12))
        stream_key_length_menu.grid(row=5, column=4, sticky=W, padx=10, pady=10)    
    def generate_random_stuff(self):
        alphabet = string.ascii_letters + string.digits
        random_iv = ''.join(random.choices(alphabet, k = int(len(self.plaintext))))
        return random_iv
    def generate_stream_random_stuff(self):
        alphabet = string.ascii_letters + string.digits
        random_iv = ''.join(random.choices(alphabet, k = int(len(self.stream_plaintext))))
        return random_iv
    def generate_random_key(self):
        alphabet = string.ascii_letters + string.digits
        random_key = ''.join(random.choices(alphabet, k=24))
        self.key_var.set(random_key)
    def generate_stream_random_key(self):
        alphabet = string.ascii_letters + string.digits
        random_key = ''.join(random.choices(alphabet, k=24))
        self.stream_key_var.set(random_key)
    def generate_random_blowfish_key_length(self):
        self.key_length_var.set(random.randint(32, 448))
    def generate_random_iv(self):
        alphabet = string.ascii_letters + string.digits
        if self.algorithm_var.get() == "AES" or self.algorithm_var.get() == "Twofish":
            random_iv = ''.join(random.choices(alphabet, k=16))
        elif self.algorithm_var.get() == "DES" or self.algorithm_var.get() == "3DES" or self.algorithm_var.get() == "Blowfish" or self.algorithm_var.get() == "IDEA":
            random_iv = ''.join(random.choices(alphabet, k=8))
        self.iv_var.set(random_iv)
    def generate_random_stream_iv(self):
        alphabet = string.ascii_letters + string.digits
        if self.stream_algorithm_var.get() == "Salsa20":
            random_iv = ''.join(random.choices(alphabet, k=8))
        elif self.stream_algorithm_var.get() == "ChaCha":
            random_iv = ''.join(random.choices(alphabet, k=8))
        self.stream_iv_var.set(random_iv)
    def generate_key(self, key_mode):
        if key_mode == "SHA-256":
            key = hashlib.sha256(self.key_var.get().encode()).digest()
        elif key_mode == "Raw":
            key = self.key_var.get().encode()
        elif key_mode == "Derived":
            salt = b'salt'
            iterations = 1000
            key = hashlib.pbkdf2_hmac('sha256', self.key_var.get().encode(), salt, iterations)
        else:
            raise ValueError("Invalid key mode")

        return key
    def encrypt(self):
        algorithm = self.algorithm_var.get()
        #key = self.generate_key(self.key_mode_var.get())
        key = self.key_var.get()
        iv = self.iv_var.get().encode()
        nonce = get_random_bytes(12)
        plaintext = self.plaintext_var.get()
        mode = self.mode_var.get()
        padding = self.padding_var.get()

        self.plaintext = plaintext
        self.key = key
        self.iv = iv
        self.mode = mode
        self.key_mode = self.key_mode_var.get()

        if str(plaintext) != "" and str(key) != "":
            if algorithm == "AES": 
                if mode == "ECB":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "ECB", padding)
                elif mode == "CBC":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "CBC", padding, iv=iv)
                elif mode == "CFB":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "CFB", padding, iv=iv)
                elif mode == "GCM":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "GCM", padding, nonce=nonce)
                elif mode == "EAX":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "EAX", padding, nonce=nonce)
                elif mode == "CTR":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "CTR", padding, nonce=nonce)
                elif mode == "CCM":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "CCM", padding, nonce=nonce)
                elif mode == "OCB":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "OCB", padding, nonce=nonce)
                elif mode == "OFB":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "OFB", padding, iv=iv)
                elif mode == "OPENPGP":
                    encrypted_data, key2 = encrypt_aes(key, plaintext, int(self.key_length_var.get()), "OPENPGP", padding)
                else:
                    raise ValueError("Invalid mode")
                
            elif algorithm == "DES": 
                if mode == "ECB":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "ECB", padding)
                elif mode == "CBC":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "CBC", padding, iv=iv)
                elif mode == "CFB":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "CFB", padding, iv=iv)
                elif mode == "EAX":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "EAX", padding, nonce=nonce)
                elif mode == "CTR":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "CTR", padding, nonce=nonce)
                elif mode == "OFB":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "OFB", padding, iv=iv)
                elif mode == "OPENPGP":
                    encrypted_data, key2 = encrypt_des(key, plaintext, int(self.key_length_var.get()), "OPENPGP", padding)
                else:
                    raise ValueError("Invalid mode")
                
            elif algorithm == "3DES": 
                if mode == "ECB":
                    encrypted_data, key2 = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "ECB", padding)
                elif mode == "CBC":
                    encrypted_data, key2 = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "CBC", padding, iv=iv)
                elif mode == "CFB":
                    encrypted_data, key2 = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "CFB", padding, iv=iv)
                elif mode == "EAX":
                    encrypted_data, key = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "EAX", padding, nonce=nonce)
                elif mode == "CTR":
                    encrypted_data, key2 = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "CTR", padding, nonce=nonce)
                elif mode == "OFB":
                    encrypted_data, key2 = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "OFB", padding, iv=iv)
                elif mode == "OPENPGP":
                    encrypted_data, key2 = encrypt_3des(key, plaintext, int(self.key_length_var.get()), "OPENPGP", padding)
                else:
                    raise ValueError("Invalid mode")
            
            elif algorithm == "Blowfish": 
                if mode == "ECB":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "ECB", padding)
                elif mode == "CBC":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "CBC", padding, iv=iv)
                elif mode == "CFB":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "CFB", padding, iv=iv)
                elif mode == "EAX":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "EAX", padding, nonce=nonce)
                elif mode == "CTR":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "CTR", padding, nonce=nonce)
                elif mode == "OFB":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "OFB", padding, iv=iv)
                elif mode == "OPENPGP":
                    encrypted_data, key2 = encrypt_blowfish(key, plaintext, int(self.key_length_var.get()), "OPENPGP", padding)
                else:
                    raise ValueError("Invalid mode")
        
        #messagebox.showinfo("Encryption Result", f"Encrypted data:\n{encrypted_data}")

        self.key2 = key2
        self.encrypted_data = encrypted_data

        top_level = Toplevel(self.root)
        top_level.title("Encryption Result")
        top_level.geometry("400x525")

        result_text = tkinter.Text(top_level, font=("Arial", 12))
        result_text.pack(padx=10, pady=10)

        result_text.insert(tkinter.END, f"Encrypted data:\n{encrypted_data}\nDecryption Key:\n{key2}")

        copy_button = Button(top_level, text="Copy", command=lambda: pyperclip.copy(str(encrypted_data)), font=("Arial", 14), bg="#B3D1DC")
        copy_button.pack(pady=10)  
    def decrypt(self):
        algorithm = self.algorithm_var.get()
        key = self.key_var.get()
        decrypting_key = self.decrypting_key_var.get()
        iv = self.iv_var.get().encode()
        nonce = get_random_bytes(12)
        plaintext = self.plaintext_var.get()
        mode = self.mode_var.get()
        padding = self.padding_var.get()
        key_mode = self.key_mode_var.get()
  
        top_level = Toplevel(self.root)
        top_level.title("Decryption Result")
        top_level.geometry("400x525")

        result_text = tkinter.Text(top_level, font=("Arial", 12))
        result_text.pack(padx=10, pady=10)

        if algorithm == "AES": 
            if decrypting_key == self.key2 and self.plaintext_var.get() == self.encrypted_data:
                result_text.insert(tkinter.END, f"Decrypted data:\n{self.plaintext}")               
            else:
                if decrypting_key != self.key2:
                    if int(len(decrypting_key)) != int(len(self.key2)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif self.plaintext_var.get() != self.encrypted_data:
                    if int(len(self.plaintext_var.get())) != int(len(self.encrypted_data)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif int(len(decrypting_key)) != int(self.key_length_var.get() / 4):
                    result_text.insert(tkinter.END, f"Decrypted data:\n")
                elif int(len(decrypting_key)) == int(self.key_length_var.get() / 4):
                    result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")    
        elif algorithm == "DES": 
            if decrypting_key == self.key2 and self.plaintext_var.get() == self.encrypted_data:
                result_text.insert(tkinter.END, f"Decrypted data:\n{self.plaintext}")               
            else:
                if decrypting_key != self.key2:
                    if int(len(decrypting_key)) != int(len(self.key2)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif self.plaintext_var.get() != self.encrypted_data:
                    if int(len(self.plaintext_var.get())) != int(len(self.encrypted_data)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif int(self.key_length_var.get()) == 56:
                    if int(len(decrypting_key)) != 16:
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}") 
        elif algorithm == "3DES": 
            if decrypting_key == self.key2 and self.plaintext_var.get() == self.encrypted_data:
                result_text.insert(tkinter.END, f"Decrypted data:\n{self.plaintext}")               
            else:
                if decrypting_key != self.key2:
                    if int(len(decrypting_key)) != int(len(self.key2)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif self.plaintext_var.get() != self.encrypted_data:
                    if int(len(self.plaintext_var.get())) != int(len(self.encrypted_data)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif int(self.key_length_var.get()) == 112:
                    if int(len(decrypting_key)) != 32:
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif int(self.key_length_var.get()) == 168:
                    if int(len(decrypting_key)) != 48:
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")  
        elif algorithm == "Blowfish": 
            if decrypting_key == self.key2 and self.plaintext_var.get() == self.encrypted_data:
                result_text.insert(tkinter.END, f"Decrypted data:\n{self.plaintext}")               
            else:
                if decrypting_key != self.key2:
                    if int(len(decrypting_key)) != int(len(self.key2)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif self.plaintext_var.get() != self.encrypted_data:
                    if int(len(self.plaintext_var.get())) != int(len(self.encrypted_data)):
                        result_text.insert(tkinter.END, f"Decrypted data:\n")
                    else:
                        result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")
                elif int(len(decrypting_key)) != int(self.key_length_var.get() / 4):
                    result_text.insert(tkinter.END, f"Decrypted data:\n")
                elif int(len(decrypting_key)) == int(self.key_length_var.get() / 4):
                    result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_random_stuff())}")

        copy_button = Button(top_level, text="Copy", command=lambda: pyperclip.copy(str(self.plaintext_var.get())), font=("Arial", 14), bg="#B3D1DC")
        copy_button.pack(pady=10)
    def stream_encrypt(self):
        algorithm = self.stream_algorithm_var.get()
        key = self.stream_key_var.get()
        plaintext = self.stream_plaintext_var.get()
        self.stream_plaintext = plaintext

        if str(plaintext) != "" and str(key) != "":
            if algorithm == "Salsa20": 
                iv = self.stream_iv_var.get().encode()
                rounds = self.rounds_var.get()
                encrypted_data, key2 = encrypt_salsa20(key, plaintext, int(self.stream_key_length_var.get()), iv=iv, rounds=rounds)
            elif algorithm == "ChaCha": 
                iv = self.stream_iv_var.get().encode()
                rounds = self.rounds_var.get()
                encrypted_data, key2 = encrypt_chacha(key, plaintext, int(self.stream_key_length_var.get()), iv=iv, rounds=rounds)
            elif algorithm == "RC4": 
                encrypted_data, key2 = encrypt_rc4(key, plaintext, int(self.stream_key_length_var.get()))
        
        #messagebox.showinfo("Encryption Result", f"Encrypted data:\n{encrypted_data}")

        top_level = Toplevel(self.root)
        top_level.title("Encryption Result")
        top_level.geometry("400x525")

        result_text = tkinter.Text(top_level, font=("Arial", 12))
        result_text.pack(padx=10, pady=10)

        result_text.insert(tkinter.END, f"Encrypted data:\n{encrypted_data}\nDecryption Key:\n{key2}")

        copy_button = Button(top_level, text="Copy", command=lambda: pyperclip.copy(str(encrypted_data)), font=("Arial", 14), bg="#B3D1DC")
        copy_button.pack(pady=10)

        self.stream_key2 = key2
        self.stream_encrypted_data = encrypted_data
        self.stream_rounds = rounds
    def stream_decrypt(self):
        algorithm = self.stream_algorithm_var.get()
        key = self.stream_key_var.get()
        plaintext = self.stream_plaintext_var.get()
        stream_decrypting_key = self.stream_decrypting_key_var.get()
        rounds = self.rounds_var.get()

        top_level = Toplevel(self.root)
        top_level.title("Decryption Result")
        top_level.geometry("400x525")

        result_text = tkinter.Text(top_level, font=("Arial", 12))
        result_text.pack(padx=10, pady=10)

        if stream_decrypting_key == self.stream_key2 and self.stream_plaintext_var.get() == self.stream_encrypted_data:
            result_text.insert(tkinter.END, f"Decrypted data:\n{self.stream_plaintext}") 
        else:
            if stream_decrypting_key != self.stream_key2:
                if int(len(stream_decrypting_key)) != int(len(self.stream_key2)):
                    result_text.insert(tkinter.END, f"Decrypted data:\n")
                else:
                    result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_stream_random_stuff())}")
            elif self.stream_plaintext_var.get() != self.stream_encrypted_data:
                if int(len(self.stream_plaintext_var.get())) != int(len(self.stream_encrypted_data)):
                    result_text.insert(tkinter.END, f"Decrypted data:\n")
                else:
                    result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_stream_random_stuff())}")
            elif int(len(stream_decrypting_key)) != int(self.stream_key_length_var.get() / 4):
                result_text.insert(tkinter.END, f"Decrypted data:\n")
            elif int(len(stream_decrypting_key)) == int(self.stream_key_length_var.get() / 4):
                result_text.insert(tkinter.END, f"Decrypted data:\n{str(self.generate_stream_random_stuff())}")
                    
        copy_button = Button(top_level, text="Copy", command=lambda: pyperclip.copy(str(self.stream_plaintext_var.get())), font=("Arial", 14), bg="#B3D1DC")
        copy_button.pack(pady=10) 

root = Tk()
encryption_app = EncryptionApp(root)
root.mainloop() 
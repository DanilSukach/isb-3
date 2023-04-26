from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_asymmetric_keys() -> tuple:
    """
    Функция генерирует ключи для асимметричного шифрования
    :return: закрытый ключ и открытый ключ
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    return private_key, public_key


def encrypt_asymmetric(public_key, text: bytes) -> bytes:
    """
    Функция производит асимметричное шифрование по открытому ключу
    :param text: текст, который шифруем
    :param public_key: открытый ключ
    :return: зашифрованный текст
    """
    encrypted_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))
    return encrypted_text


def decrypt_asymmetric(private_key, text: bytes) -> bytes:
    """
    Функция расшифровывает асимметрично зашифрованный текст, с помощью закрытого ключа
    :param text: зашифрованный текст
    :param private_key: закрытый ключ
    :return: расшифрованный текст
    """
    decrypted_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=None))
    return decrypted_text
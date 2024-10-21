import sqlite3
import datetime
from typing import List, Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


KEY_TABLE_DECLARATION = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

connection = sqlite3.connect('totally_not_my_privateKeys.db')

def create_key_table():
    cursor = connection.cursor()
    cursor.execute(KEY_TABLE_DECLARATION)

def make_pem(key: RSAPrivateKey):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def save_private_key(key: RSAPrivateKey, expiration: datetime.datetime):
    date_int = int(expiration.timestamp())
    pem = make_pem(key)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, date_int));

def get_keys(expired: bool) -> List[Tuple[int, datetime.datetime, RSAPrivateKey]]:
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM keys")
    rows = cursor.fetchall()
    now = int(datetime.datetime.utcnow().timestamp())
    ret_data = []
    for row in rows:
        key_expiration = row[2]
        id = row[0]
        key_data = row[1]
        if expired == (key_expiration < now):
            ret_data.append((
                id,
                datetime.datetime.utcfromtimestamp(key_expiration),
                serialization.load_pem_private_key(key_data, backend=default_backend(), password=None)
            ))
    return ret_data

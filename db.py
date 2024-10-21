import sqlite3
import datetime
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

def execute_query(q: str):
    cursor = connection.cursor()
    cursor.execute(q)
    connection.commit()

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
    cursor.commit()

def get_keys(expired: bool) -> Tuple[int, datetime.datetime, RSAPrivateKey]:
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM keys")
    rows = cursor.fetchall()
    now = datetime.datetime.utcnow()
    ret_data = []
    for row in rows:
        key_expiration = row['exp']
        id = row['kid']
        key_data = row['key']
        if expired == key_expiration < now:
            ret_data.append((
                id,
                datetime.datetime.utcfromtimestamp(key_expiration),
                serialization.serialization.load_pem_private_key(key_data, backend=default_backend()
            )))
    return ret_data

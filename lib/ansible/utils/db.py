import os
import sqlite3

from cryptography.fernet import Fernet

from ansible.module_utils.six.moves import cPickle as pickle


def write(db, key, value):
    new = False
    if not os.path.isfile(db):
        new = True

    conn = sqlite3.connect(db)
    conn.text_factory = bytes
    cursor = conn.cursor()
    if new:
        cursor.execute('CREATE TABLE store (key text, value text)')

    e_key = Fernet.generate_key()
    f = Fernet(e_key)
    data = f.encrypt(pickle.dumps(value))

    cursor.execute('INSERT INTO store VALUES (?, ?)', (key, data))

    conn.commit()
    conn.close()

    return key, e_key


def read(db, key, e_key):
    conn = sqlite3.connect(db)
    conn.text_factory = bytes
    cursor = conn.cursor()

    cursor.execute('SELECT value FROM store WHERE key=?', (key,))
    data = cursor.fetchone()[0]
    cursor.execute('DELETE FROM store where key=?', (key,))

    conn.commit()
    conn.close()

    f = Fernet(e_key)
    value = pickle.loads(f.decrypt(data))
    return key, value

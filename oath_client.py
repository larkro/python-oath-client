#!/usr/bin/python3
import base64
import getpass
import os
import sys
import random
import string
import argparse
import sqlite3
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os.path import expanduser
import time
import pyotp

homeDir = expanduser("~")
default_db_file = homeDir + "/.oath_auth2.db"
# os.umask(0066)


class OathDb():
    """ Provides access to database with information for OATH secrets. """
    def __init__(self, filename):
        self.filename = filename
        self.conn = sqlite3.connect(self.filename)
        self.conn.row_factory = sqlite3.Row

    def get(self, key):
        """ Fetch entry from database. """
        c = self.conn.cursor()
        for row in c.execute("SELECT account, secret, rounds, salt FROM oath WHERE account = ?", (key,)):
            return OathEntry(row)
        raise Exception("OATH token for '%s' not found in database (%s)" % (key, self.filename))

    def list_accounts(self):
        """ List all accounts in db """
        c = self.conn.cursor()
        for row in c.execute("SELECT * FROM oath ORDER BY account"):
            if (row[4] != None):
                print(row[0] + " : " + row[4])
            else:
                print(row[0])

    def get_account(self):
        """ Fetch the main account """
        c = self.conn.cursor()
        for row in c.execute("SELECT shash,salt,rounds FROM login where numb = 1"):
            return OathEntry(row)

    def create_table(self):
        """ Create tables/db if it doesnt exist """
        c = self.conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS oath (account TEXT PRIMARY KEY, secret TEXT, rounds INTEGER, salt TEXT, desc TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS login (shash TEXT PRIMARY KEY, numb INTEGER, rounds INTEGER, salt TEXT)")

    def add(self, entry):
        """ Add entry to database. """
        c = self.conn.cursor()
        c.execute("INSERT INTO oath (account, secret, rounds, salt, desc) VALUES (?, ?, ?, ?, ?)", (entry.data["account"], \
            entry.data["secret"], \
            entry.data["rounds"], \
            entry.data["salt"], \
            entry.data["desc"],))
        self.conn.commit()
        return c.rowcount == 1

    def addlogin(self, entry):
        """ Add a login entry to database. """
        c = self.conn.cursor()
        c.execute("INSERT INTO login (shash, numb, rounds, salt) VALUES (?, ?, ?, ?)", (entry.data["shash"], 1, \
            entry.data["rounds"], \
            entry.data["salt"],))
        self.conn.commit()
        return c.rowcount == 1

    def delete(self, entry):
        """ Delete entry from database. """
        c = self.conn.cursor()
        c.execute("DELETE FROM oath WHERE account = ?", (entry.data["delete"],))
        self.conn.commit()


class OathEntry():
    """ Class to hold a row of OathDb. """
    def __init__(self, row):
        if row:
            self.data = row


def generate_random_salt():
    """
    Generate a random salt of  24 bytes
    This should not be considered a secure random
    string, just a salt, its no secret.
    """
    salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(24))
    return salt


def generate_random_rounds():
    """
    Generate a random number of rounds
    of iterations. This should not be considered
    a secure random number, just number of iterations,
    its no secret.
    """
    rounds = random.randint(100000, 200000)
    return rounds


def list_accounts():
    """  List availible accounts if any """
    db = OathDb(args.db_file)
    try:
        db.list_accounts()
    except sqlite3.IntegrityError as e:
        sys.stderr.write("ERROR: %s\n" % (e))
        return False
    return True


def display_oath():
    """ login, decrypt key, decrypt client and display otp """
    db = OathDb(args.db_file)
    try:
        login = db.get_account()
    except sqlite3.IntegrityError as e:
        sys.stderr.write("ERROR: %s\n" % (e))
    print("Please unlock the database")
    password = bytes(str(getpass.getpass()), encoding='utf8')
    kdfl = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt = login.data["salt"],
        iterations = login.data["rounds"],
        backend=default_backend()
    )
    keyl = base64.urlsafe_b64encode(kdfl.derive(password))
    fl = Fernet(keyl)
    try:
        unlock = fl.decrypt(login.data["shash"])
    except Exception:
        print("Thats not correct.")
        sys.exit(1)
    db = OathDb(args.db_file)
    try:
        db_acc = db.get(args.otp)
    except sqlite3.IntegrityError as e:
        sys.stderr.write("ERROR: %s\n" % (e))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt = db_acc.data["salt"],
        iterations = db_acc.data["rounds"],
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(unlock))
    f = Fernet(key)
    totp = pyotp.TOTP(f.decrypt(db_acc.data["secret"]))
    tick = totp.now()
    print(db_acc.data["account"] + " : " + tick,)
    print("Valid for ", end = '')
    now = int((datetime.datetime.now().strftime('%S')))
    if (now < 30):
        valid = 30 - now
        print(valid, end = '')
        print(" more seconds.")
        if (valid < 6):
            print("short time left, will generate a new one for you, hang on")
            time.sleep(6)
            print(db_acc.data["account"] + " : " + totp.now())
    else:
        valid = 60 - now
        print(valid, end = '')
        print(" more seconds.")
        if (valid < 6):
            print("short time left, will generate a new one for you, hang on")
            time.sleep(6)
            print(db_acc.data["account"] + " : " + totp.now())


def create_pwstring():
    """ Store a account """
    db = OathDb(args.db_file)
    try:
        login = db.get_account()
    except sqlite3.IntegrityError as e:
        sys.stderr.write("ERROR: %s\n" % (e))
    print("Please unlock the database")
    password = bytes(str(getpass.getpass()), encoding='utf8')
    kdfl = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt = login.data["salt"],
        iterations = login.data["rounds"],
        backend=default_backend()
    )
    keyl = base64.urlsafe_b64encode(kdfl.derive(password))
    fl = Fernet(keyl)
    try:
        unlock = fl.decrypt(login.data["shash"])
    except Exception:
        print("Thats not correct.")
        sys.exit(1)
    secret = bytes(input("Enter Base32 Encoded OATH Secret for the account, it will be stored encrypted: "), encoding='utf8')
    salt = bytes(str(generate_random_salt()), encoding='utf8')
    iterations = generate_random_rounds()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt = salt,
        iterations = iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(unlock))
    f = Fernet(key)
    token = f.encrypt(secret)
    data = {"account": args.create,
        "secret": token,
        "rounds": iterations,
        "salt": salt,
        "desc": args.desc,
    }
    entry = OathEntry(data)
    db = OathDb(args.db_file)
    try:
        db.add(entry)
    except sqlite3.IntegrityError as e:
        sys.stderr.write("ERROR: %s\n" % (e))
        return False
    return True


def create_login(pwd):
    """ Create main account used for encrypting oath accounts """
    password = bytes(str(pwd), encoding='utf8')
    shash = bytes(str(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(128))), encoding='utf8')
    salt = bytes(str(generate_random_salt()), encoding='utf8')
    iterations = generate_random_rounds()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt = salt,
        iterations = iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(shash)

    data = {"shash": token,
        "rounds": iterations,
        "salt": salt,
    }
    entry = OathEntry(data)
    db = OathDb(args.db_file)
    try:
        db.addlogin(entry)
    except sqlite3.IntegrityError as e:
        sys.stderr.write("ERROR: %s\n" % (e))
        return False
    return True


def delete_account():
    """ Delete account """
    data = {"delete": args.delete}
    entry = OathEntry(data)
    db = OathDb(args.db_file)
    try:
        db.delete(entry)
    except sqlite3.Error as e:
        sys.stderr.write("ERROR: %s\n" % (e))
        return False
    return True


def parse_args():
    """ argument parser """
    parser = argparse.ArgumentParser(description='OATH Authenticator',
        add_help=True, formatter_class=argparse.ArgumentDefaultsHelpFormatter,)
    parser.add_argument('-l','--list',action='store_true', dest='list', help='List possible OATH accounts', required=False)
    parser.add_argument('-r','--remove', dest='delete', help='Remove OATH account', metavar='ACCOUNT', required=False)
    parser.add_argument('-c','--create', dest='create', help='Create OATH account', metavar='ACCOUNT', required=False)
    parser.add_argument('-d','--desc', dest='desc', help='description of the account, optionally', required=False)
    parser.add_argument('-o','--otp', dest='otp', help='Get an otp from an account', metavar='ACCOUNT', required=False)
    parser.add_argument('-D','--db-file', dest='db_file', default=default_db_file, required=False,
        help='DB file for storing oath accounts', metavar='FN',)
    return parser.parse_args()


def main():
    """ main shiznitz """
    global args
    args = parse_args()

    if os.path.isfile(args.db_file):
        pass
    else:
        print("Database file " + args.db_file + " does not exists")
        answer = input("Do you want to create it? (y/n): ")
        if answer.lower() == "y":
            print("Enter a password to be used for decrypting the accounts: ")
            password = getpass.getpass()
            print("And again: ")
            password2 = getpass.getpass()
            if (password == password2):
                pass
            else:
                print("The passwords did not match.")
                sys.exit(1)
            if (len(password) < 8):
                print("Please pick a longer password.")
                sys.exit(1)
            db = OathDb(args.db_file)
            try:
                db.create_table()
                create_login(password)
            except sqlite3.IntegrityError as e:
                sys.stderr.write("ERROR: %s\n" % (e))
                return False
            return True
        else:
            print("Ok then, exiting..")
            sys.exit(1)
    if args.create:
        create_pwstring()
    if args.otp:
        display_oath()
    if args.delete:
        print("Deleting account " + args.delete + " if it exists")
        delete_account()
        print("Accounts in db now:")
        list_accounts()
    if args.desc:
        if not args.create:
            print( "-d This is only used in combo with --create/-c")
    if args.list:
        print("Accounts in db:")
        list_accounts()


if __name__ == "__main__":
    main()

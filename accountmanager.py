# -*- coding: utf-8 -*-
import sys, base64
import json, requests
import getpass
from passlib.hash import pbkdf2_sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

requests.packages.urllib3.disable_warnings()

client_priv_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=1024,
                    backend=default_backend()
                  )
client_pub_key = client_priv_key.public_key()
pem_client_pub_key = client_pub_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                     )
server_pub_key = None
ticket = None

CERT = "./certs/cert.pem"

def usage():
    print "Usages: "
    print "create -name LSD.user -easy xxxx -hard XXXXXXXXXXXXXXX"
    print "remove -name LSD.user"
    print "\nLSD.user is the name of the user"
    print "xxxx is a 4-digit password"
    print "XXXXXXXXXXXXXXX is a password with 15 characters at maximum size"


def encrypt(message): #TODO add try..catch
    encrypted_msg = server_pub_key.encrypt(
                        message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                            algorithm=hashes.SHA1(),
                            label=None
                        )
                       )
    return encrypted_msg

def decrypt(enc_message):
    message = client_priv_key.decrypt(
                enc_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
        )
    )
    return message

def hash_data(data, username):
    hash = pbkdf2_sha256.hash(data, salt=username, rounds=15000)
    return hash

def read_easy(username):
    easy = ""   
    while len(easy) != 4 or not(easy.isdigit()):
        easy = getpass.getpass("Easy password (4 digit number): ")
    return easy

def read_hard(username):
    hard = ""
    while len(hard) < 8 or len(hard) > 15:
        hard = getpass.getpass("Hard password (8 characters at minimum; 15 at maximum): ")
    return hard

def read_access_level():
    access_level = ""   
    while len(access_level) != 1 or not(access_level.isdigit()):
        access_level = raw_input("Access level (0 for admin; any other 1-digit number for basic user): ")
    return access_level
    

def read_user_data():  
    username = base64.b64encode(encrypt(raw_input("Username: ")))
    easy = base64.b64encode(encrypt(read_easy(username)))
    hard = base64.b64encode(encrypt(read_hard(username)))
    mac = base64.b64encode(encrypt(raw_input("MAC: ")))
    access_level = read_access_level()
    return {"username": username, "easy": easy, "hard": hard, "mac": mac, "access_level": access_level}

def read_admin_data():
    admin = base64.b64encode(encrypt(raw_input("Admin username: ")))
    hard = base64.b64encode(encrypt(getpass.getpass("Hard password (8-15 characters): ")))
    return {"admin_username": admin, "hard": hard}

def create_user():
#    admin = read_admin_data()
    user = read_user_data()
    r = requests.post("https://localhost:8008/users", json={"user_data": user, "ticket": base64.b64encode(encrypt(ticket))}, verify=CERT).json()
    print r

def update_user():    
#    admin = read_admin_data()
    user = read_user_data()
    r = requests.put("https://localhost:8008/users", json={"user_data": user, "ticket": base64.b64encode(encrypt(ticket))}, verify=CERT).json()
    print r

def remove_user():
    admin = read_admin_data()
    username = raw_input("Username: ")
    payload = {"admin_data": admin, "ticket": base64.b64encode(encrypt(ticket))}
    r = requests.delete("https://localhost:8008/users/%s" % username, json=payload, verify=CERT).json()
    print r

def list_users(): #TODO add try..catch
#    admin = read_admin_data()
#    payload = {"admin_data": admin, "ticket": base64.b64encode(encrypt(ticket))}
    r = requests.get("https://localhost:8008/users", verify=CERT).json()
    print r

def get_server_key():
    payload = {"public_key": base64.b64encode(pem_client_pub_key)}
    r = requests.get("https://localhost:8008/pubkey", params=payload, verify=CERT)
    data = r.json()
    if r.status_code == 200:
        return base64.b64decode(data["public_key"]), decrypt(base64.b64decode(data["ticket"]))
    return ""

def main():
    global server_pub_key, ticket
    pem_server_pub_key, ticket = get_server_key()
    server_pub_key = serialization.load_pem_public_key(pem_server_pub_key, backend=default_backend())

    args = sys.argv[1:]  
    command = str.lower(args[0]) if args[0] !=  None else ""
    if command == "create":       
        create_user()
    elif command == "remove":
        remove_user()
    elif command == "update":
        update_user()
    elif command == "list":
        list_users()
    else:
        usage()        


if __name__ == "__main__":
    main()


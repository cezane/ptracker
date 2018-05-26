from flask import Flask, request
from flask_restful import Resource, Api
from flask_pymongo import PyMongo
from passlib.hash import pbkdf2_sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json, uuid, base64, requests

app = Flask(__name__)
app.config["MONGO_DBNAME"] = "2factor_auth_db"
app.config["MONGO_URI"] = "mongodb://localhost:27017"

cert_key = "./certs/key.pem"
cert = "./certs/cert.pem"

api = Api(app)
mongo = PyMongo(app, config_prefix="MONGO")

server_priv_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=1024,
                    backend=default_backend()
                  )
server_pub_key = server_priv_key.public_key()
pem_server_pub_key = server_pub_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                     )

#print server_pub_key
#print pem_server_pub_key

class Users(Resource):

    def exist_user(self, username):
        return mongo.db.users.find_one({"username": username})

    def hash_data(self, data, username):
        hash = pbkdf2_sha256.hash(data, salt=username, rounds=15000)
        return hash

 
    def login(self, username, hard):        
        if not self.exist_user(username):
            data = {"response":"There is no such user (%s)." % username, "code": 0}
            return json.dumps(data)

        u = mongo.db.users.find_one({"username": username})
        hardpass = u["hard"]
        admin = u["access_level"]

        if admin != "0":
            data = {"response":"User %s has no privilege to use this application." % username, "code": 0}
        elif self.hash_data(hard, username) == hardpass:
            data = {"response":"Authenticated user.", "code": 1}
        else:
            data = {"response": "Authentication failed for user %s." % username, "code": 0}

        return json.dumps(data)

    def authorize_request(self, data):
        ticket = Crypt.decrypt(base64.b64decode(data["ticket"]))
        checked_ticket = json.loads(Crypt.check_ticket(ticket))
        
        if checked_ticket["code"] == 0:
            return json.dumps(checked_ticket)

#        admin_username = Crypt.decrypt(base64.b64decode(data["admin_data"]["admin_username"]))
#        admin_hard = Crypt.decrypt(base64.b64decode(data["admin_data"]["hard"]))
#        auth_admin = json.loads(self.login(admin_username, admin_hard))
        
#        if auth_admin["code"] == 0:
#            return json.dumps(auth_admin)
        
        return json.dumps({"response": "Request authorized: ticket and user validated.", "code": 1})

    def create_entity(self, mac):
        ORION_URL = "http://localhost:1026/v2/entities"
        headers = {'content-type': 'application/json','accept': 'application/json'}

        payload = '{ \
              "id": "'+ str(mac) +'", \
              "type": "mobile_phone", \
              "location": {  \
                          "type": "room", \
                          "value": ""}  }'

        try:
          #HEADERS.update({'X-Auth-Token': token})
          r = requests.post(ORION_URL, data=payload, headers=headers)
          if r.status_code in (200, 201):
             print "The status of this operation is: " + str(r.status_code) + " OK! Successful register!" 
          else:
             print " Some error occurred! Status: " + str(r.status_code)
             print r.text
        except requests.exceptions.RequestException as e:
             print e
             sys.exit(1)


    def get(self):
        data = request.get_json()
        #auth_response = json.loads(self.authorize_request(data))
        #if auth_response["code"] == 0:
        #   return auth_response["response"]

        users = mongo.db.users.find()
        if not users:
            return "There is no record of users yet."
        usernames_list = ""
        for u in users:
            print u
            usernames_list += "   " + u["username"]
        return "Listing all the usernames: %s." % usernames_list
    
    def post(self):
        data = request.get_json()
        if not data:
            data = {"response": "error: you must pass the right params."}
            return json.dumps(data)

        auth_response = json.loads(self.authorize_request(data))
        if auth_response["code"] == 0:
           return auth_response["response"]

        new_username = Crypt.decrypt(base64.b64decode(data["user_data"]["username"]))
        if not self.exist_user(new_username):
            easy = self.hash_data(Crypt.decrypt(base64.b64decode(data["user_data"]["easy"])), new_username)
            hard = self.hash_data(Crypt.decrypt(base64.b64decode(data["user_data"]["hard"])), new_username)
            mac = Crypt.decrypt(base64.b64decode(data["user_data"]["mac"]))
            access_level = data["user_data"]["access_level"]

            new_user_data = {"username": new_username, "easy": easy, "hard": hard, "mac": mac, "access_level": access_level}
            user_id = mongo.db.users.insert_one(new_user_data).inserted_id
            self.create_entity(mac)
            return "User %s successfully created with the id %s!" % (new_username, user_id)

        return "There is already a registered user with \"%s\" username." % new_username

    def delete(self, username):
        data = request.get_json()
        auth_response = json.loads(self.authorize_request(data))
        if auth_response["code"] == 0:
           return auth_response["response"]

        if self.exist_user(username):
            user_id = mongo.db.users.delete_one({"username": username})
            print user_id
            return "User %s successfully removed!" % username
        return "There is no user registered with \"%s\" username." % username

    def put(self):
        data = request.get_json()
        if not data:
            data = {"response": "there was no data in the request to update."}
            return json.dumps(data)

        auth_response = json.loads(self.authorize_request(data))
        if auth_response["code"] == 0:
           return auth_response["response"]

        #TODO Add try..catch
        new_username = Crypt.decrypt(base64.b64decode(data["user_data"]["username"]))
        hash_easy = self.hash_data(Crypt.decrypt(base64.b64decode(data["user_data"]["easy"])), new_username)
        hash_hard = self.hash_data(Crypt.decrypt(base64.b64decode(data["user_data"]["hard"])), new_username)
        access_level = data["user_data"]["access_level"]
        if self.exist_user(new_username):
            mongo.db.users.update_one({"username": new_username}, {"$set": {"easy": hash_easy, "hard": hash_hard, "access_level": access_level} })
            return "Attributes for user %s successfully updated." % new_username

        return "It was not possible to update: there is no such user (%s)!" % new_username


class Crypt(Resource):
    
    tickets = []
    client_pub_key = None

    @staticmethod
    def create_ticket():
        ticket = uuid.uuid4().hex + uuid.uuid1().hex
        Crypt.tickets.append(ticket)
        print Crypt.tickets       
        return ticket

    @staticmethod
    def check_ticket(ticket):
        if ticket not in Crypt.tickets:
            return json.dumps({"response": "You do not have a valid ticket!", "code": 0})
        Crypt.tickets.remove(ticket)
        return json.dumps({"response": "Valid token!", "code": 1})

    @staticmethod
    def encrypt(message): #TODO add try..catch
        encrypted_msg = Crypt.client_pub_key.encrypt(
                            message, 
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                algorithm=hashes.SHA1(),
                                label=None
                            )
                           )
        return encrypted_msg

    @staticmethod
    def decrypt(enc_message):
        message = server_priv_key.decrypt(
                enc_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
        )
        return message

    def get(self):
        try:
            data = request.args
            pem_client_pub_key = base64.b64decode(data["public_key"])
            Crypt.client_pub_key = serialization.load_pem_public_key(pem_client_pub_key, backend=default_backend())
            encrypted_ticket = Crypt.encrypt(Crypt.create_ticket())
            message = {"ticket": base64.b64encode(encrypted_ticket), "public_key": base64.b64encode(pem_server_pub_key), "message": "OK"}
            return message
        except ValueError:
            return {"message": "Some error occurred! Maybe a problem with your key."}


api.add_resource(Users, "/users", endpoint="users")
api.add_resource(Users, "/users/<string:username>", endpoint="removal")
api.add_resource(Crypt, "/pubkey", endpoint="pubkey")


if __name__ == '__main__':
    app.run(port='8008', ssl_context=(cert, cert_key))
 

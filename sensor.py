import requests, sys

def update_entity(mac, room):
    ORION_URL = "http://localhost:1026/v2/entities"
    headers = {'content-type': 'application/json'}

    payload = '{ "location": {  \
                          "type": "room", \
                          "value": "' + room + '" } }'

    print payload
    try:
        r = requests.post(ORION_URL+"/"+mac+"/attrs/", data=payload, headers=headers)
        print "The status of this operation is: " + str(r.status_code) + (" OK! Successful operation!"
              if r.status_code==201 or r.status_code==200 or r.status_code==204 else " Some error occurred!")
        print r.text
    except requests.exceptions.RequestException as e:
        print "EITA"
        print e
    except requests.exceptions.SSLError as e:
        print "VIXE"
        print e.response 

def main():
#    global server_pub_key, ticket
#    pem_server_pub_key, ticket = get_server_key()
#    server_pub_key = serialization.load_pem_public_key(pem_server_pub_key, backend=default_backend())

    args = sys.argv[1:]  
    command = str.lower(args[0])
    if command == "sense":
        mac = raw_input("MAC: ")
        room = raw_input("Room: ")
        update_entity(mac, room)
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


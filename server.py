from flask import Flask, request, jsonify
from datetime import datetime
import jwt
from pymongo import MongoClient


app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'tuilakhomuchihi'

# MongoDB connection
client = MongoClient('mongodb+srv://test:test@cluster0.pcwlbuz.mongodb.net/?retryWrites=true&w=majority')
db = client['cauca']
users_collection = db['user']

@app.route('/', methods=['GET'])
def index():
    return 'Hello guys!'

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    mac_address = data.get('mac_address')  # New line to get the MAC address

    user = users_collection.find_one({'username': username, 'password': password})
    
    if user:
        expiration_time = user.get('expiration_time')
        if expiration_time and datetime.utcnow() < datetime.utcfromtimestamp(int(expiration_time)):
            # Check if the MAC address exists in the user's document
            if 'mac_address' in user:
                # Check if the provided MAC address matches the one in the database
                if user.get('mac_address') == mac_address:
                    token_payload = {'username': username, 'mac_address': mac_address, 'exp': expiration_time}
                    token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'])
                    return jsonify({'token': token}), 200
                else:
                    return jsonify({'message': 'Unauthorized MAC address'}), 401
            else:
                # Generate a new MAC address if it doesn't exist in the database
                users_collection.update_one({'_id': user['_id']}, {'$set': {'mac_address': mac_address}})
                token_payload = {'username': username, 'mac_address': mac_address, 'exp': expiration_time}
                token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'])
                return jsonify({'token': token}), 200
        else:
            return jsonify({'message': 'Your account has expired. Please contact support.'}), 401
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# Function to check token expiration
def check_token_expiration(token, mac_address):
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        exp = decoded_token.get('exp')
        if exp and datetime.utcnow() < datetime.utcfromtimestamp(int(exp)):
            # Check if the provided MAC address matches any of the MAC addresses associated with the token
            token_mac_address = decoded_token.get('mac_address')
            if mac_address == token_mac_address:
                return True  # Token is valid and not expired, and MAC address matches
    except jwt.ExpiredSignatureError:
        pass  # Token has expired
    except jwt.InvalidTokenError:
        pass  # Invalid token
    return False

@app.route('/check_token', methods=['POST'])
def check_token():
    data = request.json
    token = data.get('token')
    mac_address = data.get('mac_address')  # Extract MAC address from the request data
    
    if token:
        if check_token_expiration(token, mac_address):  # Pass MAC address to the check_token_expiration function
            return jsonify({'valid': True}), 200
        else:
            return jsonify({'valid': False, 'message': 'Token expired or invalid'}), 401
    else:
        return jsonify({'valid': False, 'message': 'Token missing'}), 400


if __name__ == '__main__':
    app.run(debug=True)

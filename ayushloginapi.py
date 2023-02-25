from flask import Flask, jsonify,  url_for, request, session, redirect
from bson.json_util import dumps
from bson.objectid import ObjectId
import pymongo
import re
import pyotp
import bcrypt

# flask call
app = Flask(__name__)

# connection to MongoDB
client =pymongo.MongoClient("mongodb://localhost:27017/")
db =client['AYUSH_Login']
collection =db['login']

# Global variable for OTP check
OTP = ""

# Validate the email address using a regex.
def is_email_address_valid(email):
    if not re.match("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$", email):
        return False
    return True

# send otp for authentication
def send_otp_for_authentication(id):
	totp = pyotp.TOTP('base32secret3232')
	global OTP
	OTP = totp.now()
	login_user = collection.find({"_id":ObjectId(id)})
	collection.update_one({"_id":login_user[0]['_id']},{"$set":{"OTP":int(OTP)}})

# register user
@app.route('/register', methods=['POST','GET'])
def register():
	if request.method=='POST':
		_email = request.json['email']
		_password = request.json['password']

		# Validate the email address and raise an error if it is invalid
		if not is_email_address_valid(_email):
			return jsonify("Please enter a valid email address")

		# check if email already exist or not
		if collection.find_one({'email': _email}):
			return jsonify("Email Id already exist , Enter any other valid Email...")
			
		# validate the received values
		if  _email and _password and request.method == 'POST':
			_hash_password = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
			id = collection.insert_one({ 'email': _email, 'password': _hash_password })
			return jsonify("Added Successfully")
			# redirect to login page
			#return redirect(url_for('login'))
		else:
			return not_found()

@app.route('/login', methods=['POST'])
def login():
	_email = request.json['email']
	_password = request.json['password']
	authenticate = False
	# check for user exist or not
	if collection.count_documents({'email':_email})==0:
		return jsonify("User not exist")
	login_user = collection.find({"email":_email})
	if login_user[0]['email'] == _email:
		# password matching
		if bcrypt.hashpw(_password.encode('utf-8'), login_user[0]['password']) == login_user[0]['password']:
			send_otp_for_authentication(login_user[0]['_id'])
			authenticate = True
			return jsonify("Email and Password matched , Verify Otp now")
			# redirect to verify page
			#return redirect(url_for('verify'))
	if authenticate==False:
		return jsonify("Email or Password not matched")
		
# verify user
@app.route('/verify', methods = ['POST'])
def verify():
	entered_otp = request.json['Enter OTP']
	print(type(entered_otp))
	if entered_otp == int(OTP):
		return jsonify("Login Successful")
	else:
		return jsonify("Login Failed")

# update user
@app.route('/login/update/<id>', methods=['PUT'])
def update_user(id):
	_email = request.json['email']
	_password = request.json['Enter New password']		
	# validate the received values
	if _email and _password and request.method == 'PUT':
		# save password as a hashing
		_hash_password = bcrypt.hashpw(_password.encode('utf-8'), bcrypt.gensalt())
		login_user = collection.find({"_id":ObjectId(id)})
  		# save edits
		collection.update_one({"_id":login_user[0]['_id']},{"$set":{"password":_hash_password}})
		resp = jsonify('Password changed successfully!')
		resp.status_code = 200
		return resp
	else:
		return not_found()
		
# delete user 
@app.route('/delete/<id>', methods=['DELETE'])
def delete_user(id):
	collection.delete_one({'_id': ObjectId(id)})
	resp = jsonify('User deleted successfully!')
	resp.status_code = 200
	return resp
		
# display all users
@app.route('/users')
def users():
	users = collection.find()
	resp = dumps(users)
	return resp

# display single user
@app.route('/user/<id>')
def user(id):
	user = collection.find_one({'_id': ObjectId(id)})
	resp = dumps(user)
	return resp

# Error Handler
@app.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404

    return resp

# Main Function
if __name__ == "__main__":
    app.run(debug = True)
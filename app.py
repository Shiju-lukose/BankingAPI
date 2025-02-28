from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS  # 👈 Import CORS for frontend integration
import os
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)

# ✅ Set Absolute Database Path to Avoid Conflicts
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "banking.db")
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://banking_db_s1c9_user:aRaV27HIe5JWtzQlEXNAp6eWwzsqUlUv@dpg-cv0qqdtsvqrc738ul0g0-a/banking_db_s1c9"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

# ✅ Enable CORS to allow frontend to access API
CORS(app)

# ✅ Initialize Flask-Limiter to prevent brute-force attacks
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ✅ Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# ✅ Define Account Model
class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    balance = db.Column(db.Float, nullable=False, default=0.0)
    
    user = db.relationship('User', backref=db.backref('account', uselist=False))

    # ✅ Define Transaction Model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


# ✅ Create Tables if Not Exists
with app.app_context():
    db.create_all()
    print("✅ Database and tables checked successfully!")

    # ✅ Insert default admin if not exists
    if not User.query.filter_by(email="admin@example.com").first():
        admin_user = User(username="admin", email="admin@example.com", role="admin")
        admin_user.set_password("admin123")
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created!")

    # ✅ Ensure every user has an account
    users = User.query.all()
    for user in users:
        if not Account.query.filter_by(user_id=user.id).first():
            new_account = Account(user_id=user.id, balance=0.0)
            db.session.add(new_account)
            print(f"✅ Account created for {user.username} (Balance: ₹0.0)")
    
    db.session.commit()

# ✅ Admin Middleware (Ensures only admins can access admin routes)
def admin_required():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or user.role != "admin":
        return jsonify({"message": "Access forbidden: Admins only"}), 403


# ✅ User Registration Route
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or "username" not in data or "email" not in data or "password" not in data:
            return jsonify({"message": "Missing required fields"}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({"message": "Email already exists!"}), 400

        role = data.get("role", "user")
        user = User(username=data['username'], email=data['email'], role=role)
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        # ✅ Create an account for the new user
        new_account = Account(user_id=user.id, balance=0.0)
        db.session.add(new_account)
        db.session.commit()
        
        return jsonify({"message": f"{role.capitalize()} registered successfully!"}), 201
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"message": "Database error!"}), 500
    except Exception:
        return jsonify({"message": "An unexpected error occurred!"}), 500

# ✅ Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or "email" not in data or "password" not in data:
        return jsonify({"message": "Missing email or password"}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({"message": "Invalid email or password"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({"message": "Login successful!", "access_token": access_token}), 200

# ✅ Logout Route
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({"message": "Logout successful!"})
    unset_jwt_cookies(response)
    return response

# ✅ Deposit Money Route (Improved)
@app.route('/deposit', methods=['POST'])
@jwt_required()
def deposit():
    user_id = get_jwt_identity()
    data = request.get_json()

    # ✅ Ensure valid JSON is received
    if not data or "amount" not in data:
        return jsonify({"message": "Amount is required in the request!"}), 400

    # ✅ Ensure amount is a valid number
    try:
        amount = float(data["amount"])
    except ValueError:
        return jsonify({"message": "Invalid amount format. Please enter a number."}), 400

    # ✅ Prevent negative or zero deposits
    if amount <= 0:
        return jsonify({"message": "Deposit amount must be greater than zero!"}), 400

    # ✅ Set a max deposit limit (e.g., ₹10,00,000 per transaction)
    if amount > 1000000:
        return jsonify({"message": "Deposit limit exceeded! Maximum allowed is ₹10,00,000 per transaction."}), 400

    # ✅ Fetch user account
    account = Account.query.filter_by(user_id=user_id).first()
    if not account:
        return jsonify({"message": "Account not found!"}), 404

    # ✅ Perform deposit
    account.balance += amount
    db.session.commit()

    return jsonify({"message": f"₹{amount} deposited successfully!", "new_balance": account.balance}), 200


# ✅ Withdraw Money Route (Improved)
@app.route('/withdraw', methods=['POST'])
@jwt_required()
def withdraw():
    user_id = get_jwt_identity()
    data = request.get_json()

    # ✅ Ensure valid JSON is received
    if not data or "amount" not in data:
        return jsonify({"message": "Amount is required in the request!"}), 400

    # ✅ Ensure amount is a valid number
    try:
        amount = float(data["amount"])
    except ValueError:
        return jsonify({"message": "Invalid amount format. Please enter a number."}), 400

    # ✅ Prevent negative or zero withdrawals
    if amount <= 0:
        return jsonify({"message": "Withdrawal amount must be greater than zero!"}), 400

    # ✅ Set a max withdrawal limit (₹5,00,000 per transaction)
    if amount > 500000:
        return jsonify({"message": "Withdrawal limit exceeded! Maximum allowed is ₹5,00,000 per transaction."}), 400

    # ✅ Fetch user account
    account = Account.query.filter_by(user_id=user_id).first()
    if not account:
        return jsonify({"message": "Account not found!"}), 404

    # ✅ Ensure sufficient funds
    if amount > account.balance:
        return jsonify({"message": "Insufficient funds! Cannot withdraw more than available balance."}), 400

    # ✅ Perform withdrawal
    account.balance -= amount
    db.session.commit()

    return jsonify({"message": f"₹{amount} withdrawn successfully!", "new_balance": account.balance}), 200


# ✅ Check Balance Route (Enhanced)
@app.route('/balance', methods=['GET'])
@jwt_required()
def check_balance():
    user_id = get_jwt_identity()
    account = Account.query.filter_by(user_id=user_id).first()

    if not account:
        return jsonify({
            "error": True,
            "message": "Account not found! Please ensure your account is active."
        }), 404

    return jsonify({
        "error": False,
        "message": "Balance retrieved successfully!",
        "balance": round(account.balance, 2)  # ✅ Ensures balance is rounded properly
    }), 200


# ✅ Secure Transfer Money Route (Now with Enhanced Validation)
@app.route('/transfer', methods=['POST'])
@jwt_required()
def transfer():
    user_id = get_jwt_identity()
    data = request.get_json()

    # ✅ Check if data is received and contains required fields
    if not data or "recipient_id" not in data or "amount" not in data:
        return jsonify({"error": True, "message": "Recipient ID and amount are required!"}), 400

    # ✅ Ensure the amount is valid
    if not isinstance(data["amount"], (int, float)) or data["amount"] <= 0:
        return jsonify({"error": True, "message": "Transfer amount must be a positive number!"}), 400

    # ✅ Prevent users from sending money to themselves
    recipient_id = data["recipient_id"]
    if recipient_id == user_id:
        return jsonify({"error": True, "message": "You cannot transfer money to yourself!"}), 400

    sender_account = Account.query.filter_by(user_id=user_id).first()
    recipient_account = Account.query.filter_by(user_id=recipient_id).first()

    # ✅ Ensure both sender and recipient accounts exist
    if not sender_account:
        return jsonify({"error": True, "message": "Sender account not found!"}), 404

    if not recipient_account:
        return jsonify({"error": True, "message": "Recipient account not found or inactive!"}), 404

    # ✅ Ensure sender has sufficient funds
    amount = round(data["amount"], 2)  # Ensure precision
    if amount > sender_account.balance:
        return jsonify({"error": True, "message": "Insufficient funds for this transfer!"}), 400

    # ✅ Perform Transfer
    sender_account.balance -= amount
    recipient_account.balance += amount

    # ✅ Log Transaction
    transaction = Transaction(sender_id=user_id, recipient_id=recipient_id, amount=amount)
    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        "error": False,
        "message": f"₹{amount} successfully transferred to User {recipient_id}!",
        "new_balance": sender_account.balance
    }), 200


# ✅ Secure Transaction History Route (With Better Error Handling)
@app.route('/transactions', methods=['GET'])
@jwt_required()
def transaction_history():
    user_id = get_jwt_identity()

    # ✅ Fetch transactions where the user is either sender or recipient
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | (Transaction.recipient_id == user_id)
    ).order_by(Transaction.timestamp.desc()).all()

    # ✅ Handle case where no transactions exist
    if not transactions:
        return jsonify({"error": True, "message": "No transactions found for this user!"}), 404

    # ✅ Structure transaction history for clear API response
    history = [
        {
            "transaction_id": txn.id,
            "sender_id": txn.sender_id,
            "recipient_id": txn.recipient_id,
            "amount": txn.amount,
            "timestamp": txn.timestamp.strftime("%Y-%m-%d %H:%M:%S")  # ✅ Format timestamp
        }
        for txn in transactions
    ]

    return jsonify({"error": False, "message": "Transaction history retrieved successfully!", "transactions": history}), 200


# ✅ Admin Route - View All Users
@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    response = admin_required()
    if response:
        return response

    users = User.query.all()
    user_list = [{"id": u.id, "username": u.username, "email": u.email, "role": u.role} for u in users]
    return jsonify({"users": user_list}), 200

# ✅ Admin Route - Delete a User
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    response = admin_required()
    if response:
        return response

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200

# ✅ Admin Route - View All Transactions
@app.route('/admin/transactions', methods=['GET'])
@jwt_required()
def get_all_transactions():
    response = admin_required()
    if response:
        return response

    transactions = Transaction.query.all()
    transaction_list = [{
        "transaction_id": txn.id,
        "sender_id": txn.sender_id,
        "recipient_id": txn.recipient_id,
        "amount": txn.amount,
        "timestamp": txn.timestamp
    } for txn in transactions]

    return jsonify({"transactions": transaction_list}), 200

# ✅ Admin Route - View All Accounts
@app.route('/admin/accounts', methods=['GET'])
@jwt_required()
def get_all_accounts():
    response = admin_required()
    if response:
        return response

    accounts = Account.query.all()
    account_list = [{
        "account_id": acc.id,
        "user_id": acc.user_id,
        "balance": acc.balance
    } for acc in accounts]

    return jsonify({"accounts": account_list}), 200

# ✅ Run Flask
if __name__ == "__main__":
    app.run(debug=True)

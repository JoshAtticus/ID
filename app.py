from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
import uuid
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

# Create uploads directory if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

OAUTH_SCOPES = {
    "name": "Access your full name",
    "dob": "Access your date of birth",
    "email": "Access your email address",
    "profile_picture": "Access your profile picture",
    "student_number": "Access your student number",
}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_number = db.Column(db.String(6), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(255))
    sessions = db.relationship("Session", backref="user", lazy=True)
    login_history = db.relationship("LoginHistory", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Session(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(500), nullable=False)
    device_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    last_active = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    device_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    timestamp = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    action = db.Column(db.String(20), default="login")  # 'login' or 'ended'


class OAuthApp(db.Model):
    __tablename__ = "oauth_app"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    client_id = db.Column(db.String(32), unique=True, nullable=False)
    client_secret = db.Column(db.String(64), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    website = db.Column(db.String(500))
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class OAuthAuthorization(db.Model):
    __tablename__ = "oauth_authorization"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    app_id = db.Column(db.String(36), db.ForeignKey("oauth_app.id"), nullable=False)
    scopes = db.Column(db.String(500), nullable=False)  # Comma-separated list of scopes
    access_token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_used = db.Column(db.DateTime(timezone=True))


@app.route("/account/create", methods=["POST"])
def create_account():
    data = request.get_json()
    user_number = data.get("user_number")
    password = data.get("password")
    full_name = data.get("full_name")
    dob = data.get("dob")
    email = data.get("email")

    # Validate user number format
    if (
        not user_number
        or not user_number.isdigit()
        or len(user_number) != 6
        or not user_number.startswith("1")
    ):
        return jsonify({"message": "User number must be 6 digits starting with 1"}), 400

    # Validate email format
    if not email or not email.endswith("@mundaringcc.wa.edu.au"):
        return jsonify({"message": "Invalid email format"}), 400

    email_prefix = email.split("@")[0]
    if not "." in email_prefix or not all(
        part.isalpha() for part in email_prefix.split(".")
    ):
        return jsonify({"message": "Email must be in firstname.lastname format"}), 400

    if not all([password, full_name, dob]):
        return jsonify({"message": "Missing required fields"}), 400

    if User.query.filter_by(user_number=user_number).first():
        return jsonify({"message": "User number already exists"}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 409

    try:
        dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
        new_user = User(
            user_number=user_number, full_name=full_name, dob=dob_date, email=email
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Account created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating account"}), 500


@app.route("/account/login", methods=["POST"])
def login():
    data = request.get_json()
    user_number = data.get("user_number")
    password = data.get("password")

    user = User.query.filter_by(user_number=user_number).first()

    if user and user.check_password(password):
        current_time = datetime.now(timezone.utc)  # Get current UTC time

        # Generate token
        token = jwt.encode(
            {"user_number": user_number, "exp": current_time + timedelta(hours=744)},
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )

        # Create new session with explicit timestamp
        session = Session(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token=token,
            device_name=request.headers.get("User-Agent", "Unknown Device"),
            location="Unknown Location",
            last_active=current_time,
            created_at=current_time,
        )
        db.session.add(session)

        # Record login history with explicit timestamp
        login_record = LoginHistory(
            user_id=user.id,
            device_name=request.headers.get("User-Agent", "Unknown Device"),
            location="Unknown Location",
            timestamp=current_time,
        )
        db.session.add(login_record)

        db.session.commit()
        return jsonify({"token": token})

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/account/exists", methods=["POST"])
def check_user():
    data = request.get_json()
    user_number = data.get("user_number")

    user = User.query.filter_by(user_number=user_number).first()
    if user:
        return jsonify({"message": "User found"})
    return jsonify({"message": "User not found"}), 404


@app.route("/account/verify", methods=["POST"])
def verify():
    token = request.get_json().get("token")
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return jsonify({"user_number": data["user_number"]})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/account/details", methods=["GET"])
def get_user_details():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        return jsonify(
            {
                "user_number": user.user_number,
                "full_name": user.full_name,
                "email": user.email,
                "dob": user.dob.strftime("%Y-%m-%d"),
                "profile_picture": user.profile_picture,
            }
        )
    except:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/account/profile-picture", methods=["POST"])
def upload_profile_picture():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        if "file" not in request.files:
            return jsonify({"message": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"message": "No file selected"}), 400

        if file and file.filename.lower().endswith((".png", ".jpg", ".jpeg")):
            filename = secure_filename(f"{user.user_number}_{file.filename}")
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            # Delete old profile picture if it exists
            if user.profile_picture:
                old_file = os.path.join(
                    app.config["UPLOAD_FOLDER"], user.profile_picture
                )
                if os.path.exists(old_file):
                    os.remove(old_file)

            file.save(filepath)
            user.profile_picture = filename
            db.session.commit()

            return jsonify({"message": "Profile picture updated", "filename": filename})

        return jsonify({"message": "Invalid file type"}), 400
    except:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/account/recommendations", methods=["GET"])
def get_recommendations():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        recommendations = []
        if not user.profile_picture:
            recommendations.append(
                {
                    "type": "profile_picture",
                    "message": "Set a profile picture to personalise your account",
                    "action": "set_profile_picture",
                }
            )

        return jsonify({"recommendations": recommendations})
    except:
        return jsonify({"message": "Invalid token"}), 401


# Add function to clean expired sessions
def remove_expired_sessions():
    current_time = datetime.now(timezone.utc)
    try:
        expired_sessions = Session.query.all()
        for session in expired_sessions:
            try:
                jwt.decode(
                    session.token, app.config["SECRET_KEY"], algorithms=["HS256"]
                )
            except jwt.ExpiredSignatureError:
                # Create login history record for expired session
                login_record = LoginHistory(
                    user_id=session.user_id,
                    device_name=session.device_name,
                    location=session.location,
                    timestamp=current_time,
                    action="expired",
                )
                db.session.add(login_record)
                db.session.delete(session)
        db.session.commit()
    except Exception as e:
        print(f"Error cleaning expired sessions: {str(e)}")
        db.session.rollback()


# Modify get_security_data to clean expired sessions and include action
@app.route("/account/security", methods=["GET"])
def get_security_data():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        # Clean expired sessions first
        remove_expired_sessions()

        # Verify token
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        sessions = [
            {
                "id": session.id,
                "deviceName": session.device_name,
                "location": session.location,
                "lastActive": session.last_active.isoformat(),
                "current": session.token == token,
            }
            for session in user.sessions
        ]

        login_history_query = (
            LoginHistory.query.filter_by(user_id=user.id)
            .order_by(LoginHistory.timestamp.desc())
            .limit(10)
            .all()
        )

        login_history = [
            {
                "deviceName": log.device_name,
                "location": log.location,
                "timestamp": log.timestamp.isoformat(),
                "action": log.action,
            }
            for log in login_history_query
        ]

        return jsonify({"sessions": sessions, "loginHistory": login_history})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        print(f"Security data error: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500


# Modify end_session route to record the action
@app.route("/account/end-session", methods=["POST"])
def end_session():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()
        session_id = request.json.get("sessionId")

        session = Session.query.filter_by(id=session_id, user_id=user.id).first()
        if session:
            # Record session end in login history
            login_record = LoginHistory(
                user_id=user.id,
                device_name=session.device_name,
                location=session.location,
                timestamp=datetime.now(timezone.utc),
                action="ended",
            )
            db.session.add(login_record)
            db.session.delete(session)
            db.session.commit()
            return jsonify({"message": "Session ended successfully"})

        return jsonify({"message": "Session not found"}), 404
    except:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "")

    app = OAuthApp.query.filter_by(client_id=client_id).first()
    if not app or app.redirect_uri != redirect_uri:
        return "Invalid client", 400

    requested_scopes = scope.split(",")
    if not all(s in OAUTH_SCOPES for s in requested_scopes):
        return "Invalid scope", 400

    return send_from_directory("static", "authorize.html")

@app.route("/oauth/app-info", methods=["GET"])
def get_oauth_app_info():
    client_id = request.args.get("client_id")
    if not client_id:
        return jsonify({"error": "missing_client_id"}), 400
        
    oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
    if not oauth_app:
        return jsonify({"error": "invalid_client"}), 404

    return jsonify({
        "name": oauth_app.name,
        "scope_descriptions": OAUTH_SCOPES
    })
    
@app.route("/oauth/approve", methods=["POST"])
def oauth_approve():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        # Verify user token
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()
        
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Get OAuth parameters
        client_id = request.json.get("client_id")
        scope = request.json.get("scope", "")

        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({"error": "invalid_client"}), 400

        # Validate scopes
        requested_scopes = scope.split(",")
        if not all(s in OAUTH_SCOPES for s in requested_scopes):
            return jsonify({"error": "invalid_scope"}), 400

        # Create authorization
        auth = OAuthAuthorization(
            user_id=user.id,
            app_id=oauth_app.id,
            scopes=scope,
            access_token=secrets.token_urlsafe(48)
        )
        
        db.session.add(auth)
        db.session.commit()

        return jsonify({
            "code": auth.id,
            "redirect_uri": oauth_app.redirect_uri
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        db.session.rollback()
        print(f"Error approving OAuth request: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500

@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    auth_code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    app = OAuthApp.query.filter_by(
        client_id=client_id, client_secret=client_secret
    ).first()
    if not app:
        return jsonify({"error": "invalid_client"}), 401

    auth = OAuthAuthorization.query.filter_by(id=auth_code, app_id=app.id).first()
    if not auth:
        return jsonify({"error": "invalid_grant"}), 400

    access_token = secrets.token_urlsafe(48)
    auth.access_token = access_token
    auth.last_used = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify(
        {"access_token": access_token, "token_type": "Bearer", "scope": auth.scopes}
    )


@app.route("/oauth/userinfo", methods=["GET"])
def oauth_userinfo():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401

    access_token = auth_header.split(" ")[1]
    auth = OAuthAuthorization.query.filter_by(access_token=access_token).first()
    if not auth:
        return jsonify({"error": "invalid_token"}), 401

    user = User.query.get(auth.user_id)
    scopes = auth.scopes.split(",")

    response = {}
    if "name" in scopes:
        response["name"] = user.full_name
    if "dob" in scopes:
        response["dob"] = user.dob.strftime("%Y-%m-%d")
    if "email" in scopes:
        response["email"] = user.email
    if "profile_picture" in scopes and user.profile_picture:
        response["profile_picture"] = f"/static/uploads/{user.profile_picture}"
    if "student_number" in scopes:
        response["student_number"] = user.user_number

    return jsonify(response)


@app.route("/account/authorized-apps", methods=["GET"])
def get_authorized_apps():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        authorizations = OAuthAuthorization.query.filter_by(user_id=user.id).all()
        apps = []

        for auth in authorizations:
            oauth_app = OAuthApp.query.get(auth.app_id)
            if oauth_app:
                apps.append(
                    {
                        "id": auth.id,
                        "name": oauth_app.name,
                        "website": oauth_app.website,
                        "scopes": auth.scopes.split(","),
                        "last_used": (
                            auth.last_used.isoformat() if auth.last_used else None
                        ),
                        "created_at": auth.created_at.isoformat(),
                    }
                )

        return jsonify({"apps": apps})

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        print(f"Error getting authorized apps: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/account/revoke-app", methods=["POST"])
def revoke_app():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()
        app_id = request.json.get("app_id")

        if not user:
            return jsonify({"message": "User not found"}), 404

        auth = OAuthAuthorization.query.filter_by(id=app_id, user_id=user.id).first()

        if not auth:
            return jsonify({"message": "Authorization not found"}), 404

        db.session.delete(auth)
        db.session.commit()

        return jsonify({"message": "App access revoked successfully"})

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        print(f"Error revoking app: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/account/developer/apps", methods=["GET"])
def get_developer_apps():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        apps = OAuthApp.query.all()
        return jsonify(
            {
                "apps": [
                    {
                        "id": app.id,
                        "name": app.name,
                        "client_id": app.client_id,
                        "redirect_uri": app.redirect_uri,
                        "website": app.website,
                        "created_at": app.created_at.isoformat(),
                    }
                    for app in apps
                ]
            }
        )

    except Exception as e:
        print(f"Error getting developer apps: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500


@app.route("/account/developer/apps", methods=["POST"])
def create_developer_app():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.filter_by(user_number=data["user_number"]).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        app_data = request.get_json()
        new_app = OAuthApp(
            name=app_data["name"],
            client_id=secrets.token_hex(16),
            client_secret=secrets.token_hex(32),
            redirect_uri=app_data["redirect_uri"],
            website=app_data.get("website"),
        )

        db.session.add(new_app)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "App created successfully",
                    "app": {
                        "id": new_app.id,
                        "name": new_app.name,
                        "client_id": new_app.client_id,
                        "client_secret": new_app.client_secret,
                        "redirect_uri": new_app.redirect_uri,
                        "website": new_app.website,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        print(f"Error creating developer app: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500


### Static Routes ###
@app.route("/", methods=["GET"])
def home():
    return send_from_directory("static", "index.html")


@app.route("/signup")
def signup():
    return send_from_directory("static", "signup.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory("static", "dashboard.html")


@app.route("/developer")
def developer_dashboard():
    return send_from_directory("static", "developer.html")


@app.route("/authorize")
def authorize_oauth_app():
    return send_from_directory("static", "authorize.html")


# Create the database tables
def init_db():
    with app.app_context():
        # Add new column to existing table
        with db.engine.connect() as conn:
            try:
                conn.execute(
                    'ALTER TABLE login_history ADD COLUMN action VARCHAR(20) DEFAULT "login"'
                )
            except:
                pass  # Column might already exist
        db.create_all()


if __name__ == "__main__":
    init_db()  # Initialize the database
    app.run(debug=True, port=5002)

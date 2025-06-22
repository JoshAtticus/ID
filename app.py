from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_sqlalchemy import SQLAlchemy
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
import uuid
import pathlib
import secrets
from sqlalchemy import text  # Add this import at the top with other imports
from urllib.parse import urlparse
import base64

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size
app.config['COMMON_PASSWORDS_FILE'] = 'static/resources/common_passwords.txt'

db = SQLAlchemy(app)

# Create uploads directory if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

OAUTH_SCOPES = {
    "name": "Access your full name",
    "dob": "Access your date of birth",
    "email": "Access your email address",
    "profile_picture": "Access your profile picture",
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    client_id = db.Column(db.String(32), unique=True, nullable=False)
    client_secret = db.Column(db.String(64), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    website = db.Column(db.String(500))
    verified = db.Column(db.Boolean, default=False)
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


class OAuthCode(db.Model):
    __tablename__ = "oauth_code"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    app_id = db.Column(db.String(36), db.ForeignKey("oauth_app.id"), nullable=False)
    code = db.Column(db.String(64), unique=True, nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    scopes = db.Column(db.String(500), nullable=False)
    state = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime(timezone=True))


# Add this utility function after the model definitions
def update_session_activity(token):
    """Update last_active timestamp for the session associated with the token"""
    try:
        session = Session.query.filter_by(token=token).first()
        if session:
            session.last_active = datetime.now(timezone.utc)
            db.session.commit()
    except Exception as e:
        print(f"Error updating session activity: {str(e)}")
        db.session.rollback()
        
def calculate_security_score(user, sessions):
    score = 10.0
    reasons = []
    
    # Check number of active sessions
    session_count = len(sessions)
    if session_count > 3:
        deduction = min(3, (session_count - 3)) * 1.5
        score -= deduction
        reasons.append({
            'reason': f'You have {session_count} active sessions',
            'impact': f'-{deduction:.1f}',
            'action': 'review_sessions',
            'description': 'Having too many active sessions increases security risk'
        })
    
    # Check for inactive sessions (not used in last 7 days)
    current_time = datetime.now(timezone.utc)
    inactive_sessions = [s for s in sessions if s.last_active and (current_time - s.last_active.replace(tzinfo=timezone.utc)).days >= 7]
    if inactive_sessions:
        deduction = len(inactive_sessions) * 1.0
        score -= deduction
        reasons.append({
            'reason': f'{len(inactive_sessions)} inactive device(s) still signed in',
            'impact': f'-{deduction:.1f}',
            'action': 'end_inactive_sessions',
            'description': 'Consider ending sessions on devices you haven\'t used recently'
        })
    
    # Add password check
    if is_common_password(user.password_hash):
        score -= 10.0
        reasons.append({
            'reason': 'Using a common password',
            'impact': '-10.0',
            'action': 'change_password',
            'description': 'Your password is one of the most commonly used passwords. Change it immediately!'
        })
    
    return max(0, round(score, 1)), reasons

# Add this function after other utility functions
def is_common_password(password):
    """Check if password is in the common passwords list"""
    try:
        passwords_file = pathlib.Path(app.config['COMMON_PASSWORDS_FILE'])
        if not passwords_file.exists():
            # Create file with some example common passwords if it doesn't exist
            with open(passwords_file, 'w') as f:
                f.write('password\n123456\nadmin\nqwerty\n12345678\n')
        
        with open(passwords_file, 'r') as f:
            common_passwords = set(line.strip().lower() for line in f)
            return password.lower() in common_passwords
    except Exception as e:
        print(f"Error checking common passwords: {str(e)}")
        return False

@app.route("/account/create", methods=["POST"])
def create_account():
    data = request.get_json()
    password = data.get("password")
    full_name = data.get("full_name")
    dob = data.get("dob")
    email = data.get("email")

    # Validate email format
    if not email or "@" not in email:
        return jsonify({"message": "Invalid email format"}), 400

    if not all([password, full_name, dob]):
        return jsonify({"message": "Missing required fields"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 409

    try:
        dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
        
        today = datetime.now().date()
        age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
        if age < 13:
            return jsonify({"message": "You must be at least 13 years old to sign up."}), 400

        new_user = User(
            full_name=full_name,
            dob=dob_date,
            email=email,
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
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        current_time = datetime.now(timezone.utc)  # Get current UTC time

        # Generate token
        token = jwt.encode(
            {"user_id": user.id, "exp": current_time + timedelta(hours=744)},
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
    email = data.get("email")

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"message": "User found"})
    return jsonify({"message": "User not found"}), 404


@app.route("/account/verify", methods=["POST"])
def verify():
    token = request.get_json().get("token")
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        update_session_activity(token)  # Add this line
        return jsonify({"user_id": data["user_id"]})
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
        update_session_activity(token)  # Add this line
        user = User.query.get(data["user_id"])

        if not user:
            return jsonify({"message": "User not found"}), 404

        return jsonify(
            {
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
        user = User.query.get(data["user_id"])

        if "file" not in request.files:
            return jsonify({"message": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"message": "No file selected"}), 400

        if file and file.filename.lower().endswith((".png", ".jpg", ".jpeg")):
            filename = secure_filename(f"{user.id}_{file.filename}")
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
        user = User.query.get(data["user_id"])

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
        update_session_activity(token)

        # Verify token
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Calculate security score before converting sessions to dict
        security_score, score_reasons = calculate_security_score(user, user.sessions)

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

        recommendations = []
        if security_score < 6:
            recommendations.append({
                'type': 'security_review',
                'message': 'Review security suggestions to improve your security score',
                'action': 'review_security'
            })

        return jsonify({
            'sessions': sessions,
            'loginHistory': login_history,
            'securityScore': security_score,
            'scoreReasons': score_reasons,
            'recommendations': recommendations
        })
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
        user = User.query.get(data["user_id"])
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


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    if request.method == "GET":
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        scope = request.args.get("scope", "")
        state = request.args.get("state")

        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({
                "error": "invalid_client",
                "error_description": "No application found with this client ID"
            }), 400
        try:
            registered_uri = urlparse(oauth_app.redirect_uri)
            request_uri = urlparse(redirect_uri)
            if not (registered_uri.scheme == request_uri.scheme and
                    registered_uri.netloc == request_uri.netloc and
                    (not registered_uri.path or request_uri.path.startswith(registered_uri.path))):
                return jsonify({
                    "error": "invalid_redirect_uri",
                    "error_description": f"The redirect URI must be on the same domain and path as the registered one. Expected: {oauth_app.redirect_uri}, got: {redirect_uri}"
                }), 400
        except ValueError:
            return jsonify({"error": "invalid_redirect_uri", "error_description": "Malformed redirect URI"}), 400

        requested_scopes = scope.split()
        if not all(s in OAUTH_SCOPES for s in requested_scopes):
            return jsonify({
                "error": "invalid_scope",
                "error_description": f"Invalid scopes: {[s for s in requested_scopes if s not in OAUTH_SCOPES]}"
            }), 400

        # Render consent page (authorize.html) with params
        return send_from_directory("static", "authorize.html")

    # POST: User submits consent (must be authenticated)
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "invalid_request", "error_description": "Token is missing"}), 401
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        if not user:
            return jsonify({"error": "invalid_request", "error_description": "User not found"}), 404
        client_id = request.json.get("client_id")
        scope = request.json.get("scope", "")
        redirect_uri = request.json.get("redirect_uri")
        state = request.json.get("state")
        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({"error": "invalid_client"}), 400
        # Validate redirect_uri
        try:
            registered_uri = urlparse(oauth_app.redirect_uri)
            request_uri = urlparse(redirect_uri)
            if not (registered_uri.scheme == request_uri.scheme and
                    registered_uri.netloc == request_uri.netloc and
                    (not registered_uri.path or request_uri.path.startswith(registered_uri.path))):
                return jsonify({"error": "invalid_redirect_uri"}), 400
        except ValueError:
            return jsonify({"error": "invalid_redirect_uri"}), 400
        requested_scopes = scope.split()
        if not all(s in OAUTH_SCOPES for s in requested_scopes):
            return jsonify({"error": "invalid_scope"}), 400
        # Issue authorization code
        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        oauth_code = OAuthCode(
            user_id=user.id,
            app_id=oauth_app.id,
            code=code,
            redirect_uri=redirect_uri,
            scopes=scope,
            state=state,
            expires_at=expires_at
        )
        db.session.add(oauth_code)
        db.session.commit()
        # Redirect to client with code and state
        from urllib.parse import urlencode
        params = {"code": code}
        if state:
            params["state"] = state
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        return redirect(redirect_url)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "invalid_token", "error_description": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid_token", "error_description": "Invalid token"}), 401
    except Exception as e:
        db.session.rollback()
        print(f"Error in OAuth authorize: {str(e)}")
        return jsonify({"error": "server_error"}), 500

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
        "verified": oauth_app.verified,
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
        user = User.query.get(data["user_id"])
        
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Get OAuth parameters
        client_id = request.json.get("client_id")
        scope = request.json.get("scope", "")
        redirect_uri = request.json.get("redirect_uri")

        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({"error": "invalid_client"}), 400

        # Validate redirect_uri
        if not redirect_uri:
            return jsonify({"error": "invalid_request", "details": "Missing redirect_uri"}), 400
        
        try:
            registered_uri = urlparse(oauth_app.redirect_uri)
            request_uri = urlparse(redirect_uri)

            if not (registered_uri.scheme == request_uri.scheme and
                    registered_uri.netloc == request_uri.netloc and
                    (not registered_uri.path or request_uri.path.startswith(registered_uri.path))):
                return jsonify({
                    "error": "invalid_redirect_uri",
                    "details": f"The redirect URI must be on the same domain and path as the registered one. Expected: {oauth_app.redirect_uri}, got: {redirect_uri}"
                }), 400
        except ValueError:
            return jsonify({"error": "invalid_redirect_uri", "details": "Malformed redirect URI"}), 400

        # Validate scopes
        requested_scopes = scope.split()
        if not all(s in OAUTH_SCOPES for s in requested_scopes):
            return jsonify({"error": "invalid_scope"}), 400

        # Check for existing authorization
        existing_auth = OAuthAuthorization.query.filter_by(
            user_id=user.id,
            app_id=oauth_app.id
        ).first()

        if existing_auth:
            # Update existing authorization
            existing_auth.last_used = datetime.now(timezone.utc)
            existing_auth.scopes = scope  # Update scopes in case they changed
            auth = existing_auth
        else:
            # Create new authorization
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
            "redirect_uri": redirect_uri
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
    # Start with empty client credentials
    client_id = None
    client_secret = None

    # First, try to get credentials from HTTP Basic Auth header (the secure, preferred method)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        try:
            # The header is "Basic BASE64_STRING", so we split and take the second part
            encoded_creds = auth_header.split(" ", 1)[1]
            # Decode from base64
            decoded_creds = base64.b64decode(encoded_creds).decode("utf-8")
            # Split "client_id:client_secret" into two parts
            client_id, client_secret = decoded_creds.split(":", 1)
        except (ValueError, TypeError):
            return jsonify({"error": "invalid_request", "error_description": "Malformed Authorization header"}), 400

    # If they were not in the header, fall back to checking the request body
    if not client_id:
        client_id = request.form.get("client_id")
        client_secret = request.form.get("client_secret")

    # Now, validate the credentials we found
    if not client_id:
        return jsonify({"error": "invalid_request", "error_description": "Client credentials not provided"}), 400

    oauth_app = OAuthApp.query.filter_by(client_id=client_id, client_secret=client_secret).first()
    if not oauth_app:
        # Use a print statement to be 100% sure what the server sees before failing
        print(f"Server rejected credentials: ID='{client_id}', Secret='{client_secret}'")
        return jsonify({"error": "invalid_client"}), 401

    # --- The rest of your function logic remains the same ---
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")

    if grant_type != "authorization_code":
        return jsonify({"message": "Unsupported grant_type"}), 400

    oauth_code = OAuthCode.query.filter_by(code=code, app_id=oauth_app.id).first()
    if not oauth_code or oauth_code.used:
        return jsonify({"message": "Invalid or used authorization code"}), 400
    # Ensure expires_at is timezone-aware before comparison
    expires_at = oauth_code.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return jsonify({"message": "Expired authorization code"}), 400
        
    # Split the stored URIs into a list and check if the provided one is valid
    valid_redirect_uris = oauth_app.redirect_uri.split(',')
    if redirect_uri not in valid_redirect_uris:
        return jsonify({"message": "Invalid redirect_uri"}), 400

    if oauth_code.redirect_uri != redirect_uri:
        return jsonify({"message": "Redirect URI mismatch"}), 400

    oauth_code.used = True
    db.session.commit()

    access_token = secrets.token_urlsafe(48)
    auth = OAuthAuthorization.query.filter_by(user_id=oauth_code.user_id, app_id=oauth_app.id).first()
    if not auth:
        auth = OAuthAuthorization(
            user_id=oauth_code.user_id,
            app_id=oauth_app.id,
            scopes=oauth_code.scopes,
            access_token=access_token
        )
        db.session.add(auth)
    else:
        auth.scopes = oauth_code.scopes
        auth.access_token = access_token
        auth.last_used = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": oauth_code.scopes,
    })

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
    scopes = auth.scopes.split()
    response = {
        "sub": user.id
    }
    if "name" in scopes:
        response["name"] = user.full_name
    if "dob" in scopes:
        response["dob"] = user.dob.strftime("%Y-%m-%d")
    if "email" in scopes:
        response["email"] = user.email
    if "profile_picture" in scopes:
        if user.profile_picture:
            response["profile_picture"] = f"https://id.joshattic.us/static/uploads/{user.profile_picture}"
        else:
            response["profile_picture"] = "https://id.joshattic.us/static/uploads/default.png"
    return jsonify(response)


@app.route("/account/authorized-apps", methods=["GET"])
def get_authorized_apps():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])

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
                        "verified": oauth_app.verified,
                        "scopes": auth.scopes.split() if auth.scopes else [],
                        "last_used": (
                            auth.last_used.isoformat() if auth.last_used else None
                        ),
                        "created_at": (
                            auth.created_at.isoformat() if auth.created_at else None
                        ),
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
        user = User.query.get(data["user_id"])
        client_id = request.json.get("app_id")

        if not user:
            return jsonify({"message": "User not found"}), 404

        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({"message": "Application not found"}), 404

        auth = OAuthAuthorization.query.filter_by(
            app_id=oauth_app.id, user_id=user.id
        ).first()

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
        return jsonify({"message": "Authorization token is missing"}), 401

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]
        update_session_activity(token)
        
        try:
            # Try to filter by user_id (works if migration has been applied)
            apps = OAuthApp.query.filter_by(user_id=user_id).all()
        except Exception as e:
            # If filtering by user_id fails, the column might not exist yet
            if "user_id" in str(e):
                # Try to run migrations
                perform_migrations()
                # After migration, try again with user_id filter
                try:
                    apps = OAuthApp.query.filter_by(user_id=user_id).all()
                except:
                    # If it still fails, return all apps (fallback for backward compatibility)
                    apps = OAuthApp.query.all()
            else:
                # Some other error occurred
                return jsonify({"message": f"Error retrieving apps: {str(e)}"}), 500

        return jsonify({
            "apps": [{
                "id": app.id,
                "name": app.name,
                "client_id": app.client_id,
                "redirect_uri": app.redirect_uri,
                "website": app.website,
                "created_at": app.created_at.isoformat(),
                "verified": app.verified
            } for app in apps]
        })

    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@app.route("/account/developer/apps", methods=["POST"])
def create_developer_app():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]
        update_session_activity(token)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"message": "Invalid or expired token"}), 401

    data = request.get_json()
    name = data.get("name")
    redirect_uris = data.get("redirect_uris")
    website = data.get("website")

    if not name or not redirect_uris or not isinstance(redirect_uris, list) or len(redirect_uris) == 0:
        return jsonify({"message": "Application name and at least one redirect URI are required"}), 400
    
    if len(redirect_uris) > 3:
        return jsonify({"message": "You can only have up to 3 redirect URIs"}), 400

    for uri in redirect_uris:
        parsed_uri = urlparse(uri)
        if not all([parsed_uri.scheme, parsed_uri.netloc]):
            return jsonify({"message": f"Invalid redirect URI: {uri}"}), 400

    try:
        new_app = OAuthApp(
            user_id=user_id,
            name=name,
            client_id=secrets.token_hex(16),
            client_secret=secrets.token_hex(32),
            redirect_uri=",".join(redirect_uris),
            website=website,
        )
        db.session.add(new_app)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # If there's an error with user_id column, try to perform the migration
        if "user_id" in str(e):
            try:
                perform_migrations()
                # Try again after migration
                new_app = OAuthApp(
                    user_id=user_id,
                    name=name,
                    client_id=secrets.token_hex(16),
                    client_secret=secrets.token_hex(32),
                    redirect_uri=",".join(redirect_uris),
                    website=website,
                )
                db.session.add(new_app)
                db.session.commit()
            except Exception as e2:
                return jsonify({"message": f"Error creating application after migration attempt: {str(e2)}"}), 500
        else:
            return jsonify({"message": f"Error creating application: {str(e)}"}), 500

    return jsonify({
        "message": "Application created successfully",
        "app": {
            "id": new_app.id,
            "name": new_app.name,
            "client_id": new_app.client_id,
            "client_secret": new_app.client_secret, # Important: only show this once
            "redirect_uris": new_app.redirect_uri.split(','),
            "website": new_app.website,
            "created_at": new_app.created_at.isoformat(),
        }
    }), 201


@app.route("/account/developer/apps/<app_id>", methods=["PUT"])
def update_developer_app(app_id):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]
        update_session_activity(token)
        
        try:
            # Try to filter by user_id (works if migration has been applied)
            app_to_update = OAuthApp.query.filter_by(id=app_id, user_id=user_id).first()
        except Exception as e:
            # If filtering by user_id fails, the column might not exist yet
            if "user_id" in str(e):
                # Run migrations
                perform_migrations()
                # After migration, try a simpler query without user_id filtering
                app_to_update = OAuthApp.query.filter_by(id=app_id).first()
            else:
                return jsonify({"message": f"Error retrieving app: {str(e)}"}), 500
                
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"message": "Invalid or expired token"}), 401

    if not app_to_update:
        return jsonify({"message": "App not found or you don't have permission to edit it"}), 404

    data = request.get_json()
    name = data.get("name")
    redirect_uris = data.get("redirect_uris")
    website = data.get("website")

    if not name or not redirect_uris or not isinstance(redirect_uris, list) or len(redirect_uris) == 0:
        return jsonify({"message": "Application name and at least one redirect URI are required"}), 400
    
    if len(redirect_uris) > 3:
        return jsonify({"message": "You can only have up to 3 redirect URIs"}), 400

    for uri in redirect_uris:
        parsed_uri = urlparse(uri)
        if not all([parsed_uri.scheme, parsed_uri.netloc]):
            return jsonify({"message": f"Invalid redirect URI: {uri}"}), 400

    app_to_update.name = name
    app_to_update.redirect_uri = ",".join(redirect_uris)
    app_to_update.website = website
    db.session.commit()

    return jsonify({"message": "Application updated successfully"})


@app.route("/account/developer/apps/<app_id>/regenerate-secret", methods=["POST"])
def regenerate_client_secret(app_id):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]
        update_session_activity(token)
        
        try:
            # Try to filter by user_id (works if migration has been applied)
            app_to_update = OAuthApp.query.filter_by(id=app_id, user_id=user_id).first()
        except Exception as e:
            # If filtering by user_id fails, the column might not exist yet
            if "user_id" in str(e):
                # Run migrations
                perform_migrations()
                # After migration, try a simpler query without user_id filtering
                app_to_update = OAuthApp.query.filter_by(id=app_id).first()
            else:
                return jsonify({"message": f"Error retrieving app: {str(e)}"}), 500
                
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"message": "Invalid or expired token"}), 401

    if not app_to_update:
        return jsonify({"message": "App not found or you don't have permission to edit it"}), 404

    # Generate a new client secret
    new_secret = secrets.token_hex(32)
    app_to_update.client_secret = new_secret
    db.session.commit()

    return jsonify({
        "message": "Client secret regenerated successfully",
        "client_secret": new_secret
    })


@app.route("/account/developer/apps/<app_id>", methods=["DELETE"])
def delete_developer_app(app_id):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]
        update_session_activity(token)
        
        try:
            # Try to filter by user_id (works if migration has been applied)
            app_to_delete = OAuthApp.query.filter_by(id=app_id, user_id=user_id).first()
        except Exception as e:
            # If filtering by user_id fails, the column might not exist yet
            if "user_id" in str(e):
                # Run migrations
                perform_migrations()
                # After migration, try a simpler query
                app_to_delete = OAuthApp.query.filter_by(id=app_id).first()
            else:
                return jsonify({"message": f"Error retrieving app: {str(e)}"}), 500
                
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"message": "Invalid or expired token"}), 401

    if not app_to_delete:
        return jsonify({"message": "App not found or you don't have permission to delete it"}), 404

    # Clean up related authorizations and codes first
    OAuthAuthorization.query.filter_by(app_id=app_to_delete.id).delete()
    OAuthCode.query.filter_by(app_id=app_to_delete.id).delete()
    
    db.session.delete(app_to_delete)
    db.session.commit()

    return jsonify({"message": "Application deleted successfully"})



# Add new route for password check
@app.route('/account/check-password', methods=['POST'])
def check_password():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        password = request.json.get('password')
        
        if not password:
            return jsonify({'message': 'Password is required'}), 400

        is_common = is_common_password(password)
        
        return jsonify({
            'is_common': is_common,
            'message': 'This is a commonly used password. Please choose a more secure password.' if is_common 
                      else 'Password not found in common passwords list.'
        })
    except:
        return jsonify({'message': 'Invalid token'}), 401

# Add new route for changing password
@app.route('/account/change-password', methods=['POST'])
def change_password():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        old_password = request.json.get('old_password')
        new_password = request.json.get('new_password')
        
        if not all([old_password, new_password]):
            return jsonify({'message': 'Both old and new passwords are required'}), 400
            
        if not user.check_password(old_password):
            return jsonify({'message': 'Current password is incorrect'}), 401
            
        if is_common_password(new_password):
            return jsonify({
                'message': 'Cannot use a common password. Please choose a more secure password.',
                'is_common': True
            }), 400
            
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password updated successfully'})
    except:
        return jsonify({'message': 'Invalid token'}), 401

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


@app.route("/privacy")
def privacy():
    return send_from_directory("static", "privacy.html")


@app.route("/terms")
def terms():
    return send_from_directory("static", "terms.html")


# Create the database tables
def init_db():
    with app.app_context():
        db.create_all()
        
        # After creating tables, check if we need to perform migrations
        perform_migrations()

def perform_migrations():
    """Check for and apply any needed database migrations"""
    try:
        # Check if user_id column exists in oauth_app table
        exists = False
        with db.engine.connect() as connection:
            # Get the column info for the oauth_app table
            result = connection.execute(text("PRAGMA table_info(oauth_app)"))
            columns = result.fetchall()
            
            # Check if user_id column exists
            for col in columns:
                if col[1] == 'user_id':  # column name is at index 1
                    exists = True
                    break
            
            # Add user_id column if it doesn't exist
            if not exists:
                print("Migrating database: Adding user_id column to oauth_app table")
                # Add the column with a default value
                connection.execute(text("ALTER TABLE oauth_app ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1"))
                
                # Create foreign key relationship in a separate statement
                # Note: SQLite has limited ALTER TABLE support, so we're setting a default value instead of a proper FK
                connection.execute(text("PRAGMA foreign_keys=off"))
                connection.execute(text("COMMIT"))
                print("Database migration completed successfully")
        
        # Check for any other migrations that might be needed in the future
        # e.g., check_other_migrations()
                
    except Exception as e:
        print(f"Error during database migration: {str(e)}")
        db.session.rollback()

if __name__ == "__main__":
    init_db()  # Initialize the database
    print("\033[91mYOU ARE RUNNING THE SERVER IN DEBUG MODE! DO NOT USE THIS IN PRODUCTION!\033[0m")
    app.run(debug=True, port=5002)

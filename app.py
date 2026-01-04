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
from sqlalchemy import text
from urllib.parse import urlparse
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import importlib.util

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL") or "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config['COMMON_PASSWORDS_FILE'] = 'static/resources/common_passwords.txt'
app.config['MAX_LOGIN_ATTEMPTS'] = 5
app.config['LOGIN_TIMEOUT'] = 300
app.config['SMTP_SERVER'] = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
app.config['SMTP_PORT'] = int(os.environ.get("SMTP_PORT", 587))
app.config['SMTP_USERNAME'] = os.environ.get("SMTP_USERNAME")
app.config['SMTP_PASSWORD'] = os.environ.get("SMTP_PASSWORD")
app.config['SMTP_FROM_EMAIL'] = os.environ.get("SMTP_FROM_EMAIL")
app.config['SMTP_FROM_NAME'] = os.environ.get("SMTP_FROM_NAME", "JoshAtticusID")

db = SQLAlchemy(app)

def run_migrations(app, db):
    migration_folder = os.path.join(os.path.dirname(__file__), 'migrations')
    if not os.path.exists(migration_folder):
        return
    
    print("Checking for migrations...")
    migration_files = sorted([f for f in os.listdir(migration_folder) if f.endswith('.py')])
    
    for filename in migration_files:
        try:
            filepath = os.path.join(migration_folder, filename)
            spec = importlib.util.spec_from_file_location("migration", filepath)
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
            if hasattr(migration, 'upgrade'):
                print(f"Running migration: {filename}")
                migration.upgrade(app, db)
        except Exception as e:
            print(f"Error running migration {filename}: {e}")

with app.app_context():
    db.create_all()
    run_migrations(app, db)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

OAUTH_SCOPES = {
    "name": "Access your full name",
    "dob": "Access your date of birth",
    "email": "Access your email address",
    "profile_picture": "Access your profile picture",
    "openid": "OpenID Connect authentication",
    "profile": "Access your basic profile information",
}


@app.route("/.well-known/openid-configuration", methods=["GET"])
def openid_configuration():
    # Ensure returned base_url always uses https
    base = request.url_root.rstrip('/')
    if base.startswith("http://"):
        base = "https://" + base.split("://", 1)[1]
    elif not base.startswith("https://"):
        base = "https://" + base

    return jsonify({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "userinfo_endpoint": f"{base}/oauth/userinfo",
        "revocation_endpoint": f"{base}/oauth/token/revoke",
        "introspection_endpoint": f"{base}/oauth/token/introspect",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": list(OAUTH_SCOPES.keys()),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "name", "email", "email_verified", "picture", "birthdate"],
        "code_challenge_methods_supported": ["S256"],
    })


@app.route("/.well-known/oauth-authorization-server", methods=["GET"])
def oauth_metadata():
    return openid_configuration()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(255))
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    sessions = db.relationship("Session", backref="user", lazy=True)
    login_history = db.relationship("LoginHistory", backref="user", lazy=True)
    has_accepted_legal = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class EmailVerification(db.Model):
    __tablename__ = "email_verification"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True))
    verified = db.Column(db.Boolean, default=False)


class PasswordReset(db.Model):
    __tablename__ = "password_reset"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True))
    used = db.Column(db.Boolean, default=False)


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
    banned = db.Column(db.Boolean, default=False, nullable=False)
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
    usage_count = db.Column(db.Integer, default=0)


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
    try:
        passwords_file = pathlib.Path(app.config['COMMON_PASSWORDS_FILE'])
        if not passwords_file.exists():
            os.makedirs(passwords_file.parent, exist_ok=True)
            with open(passwords_file, 'w') as f:
                f.write('password\n123456\nadmin\nqwerty\n12345678\n')
        
        with open(passwords_file, 'r') as f:
            common_passwords = set(line.strip().lower() for line in f)
            return password.lower() in common_passwords
    except Exception as e:
        print(f"Error checking common passwords: {str(e)}")
        return False

def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if is_common_password(password):
        return False, "Password is too common"
    return True, "Password is strong"

def sanitize_redirect_url(url, allowed_domains=None):
    if not url:
        return None
    if allowed_domains is None:
        allowed_domains = ['id.joshattic.us', 'localhost']
    try:
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in ['http', 'https']:
            return None
        if parsed.netloc and parsed.netloc not in allowed_domains:
            return None
        return url
    except Exception:
        return None

def send_verification_email(email, code):
    try:
        if not all([app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'], app.config['SMTP_FROM_EMAIL']]):
            print("SMTP configuration is missing")
            return False

        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Verify Your Email - JoshAtticusID'
        msg['From'] = f"{app.config['SMTP_FROM_NAME']} <{app.config['SMTP_FROM_EMAIL']}>"
        msg['To'] = email

        text_content = f"""
Hello,

Thank you for signing up for JoshAtticusID!

Your verification code is: {code}

This code will expire in 15 minutes.

If you didn't request this verification, please ignore this email.

You are recieving this email because you signed up for a JoshAtticusID account. If this was not you, please ignore this email and nothing will happen.
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #8ab4f8;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .code {{
            background: rgba(138, 180, 248, 0.1);
            border: 2px solid #8ab4f8;
            border-radius: 8px;
            padding: 24px;
            text-align: center;
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #8ab4f8;
            margin: 24px 0;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Verify Your Email</h1>
        <p>Thank you for signing up for JoshAtticusID!</p>
        <p>Your verification code is:</p>
        <div class="code">{code}</div>
        <p>This code will expire in 15 minutes.</p>
        <p>If you didn't request this verification, please ignore this email.</p>
        <div class="footer">
            <small>You are recieving this email because you signed up for a JoshAtticusID account. If this was not you, please ignore this email and nothing will happen.</small>
        </div>
    </div>
</body>
</html>
"""

        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
            server.starttls()
            server.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


def send_email(to_email, subject, text_content, html_content):
    """General email sending function"""
    try:
        if not all([app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'], app.config['SMTP_FROM_EMAIL']]):
            print("SMTP configuration is missing")
            return False

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{app.config['SMTP_FROM_NAME']} <{app.config['SMTP_FROM_EMAIL']}>"
        msg['To'] = to_email

        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
            server.starttls()
            server.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


def send_new_signin_email(user, device_info, location="Unknown"):
    """Send email notification for new sign-in"""
    text_content = f"""
Hello {user.full_name},

We detected a new sign-in to your JoshAtticusID account.

Device: {device_info}
Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Location: {location}

If this was you, you can safely ignore this email.

If you don't recognize this sign-in, please secure your account immediately by changing your password.

You are recieving this email because someone signed into your JoshAtticusID from a device or location we don't recognize.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #8ab4f8;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .info-box {{
            background: rgba(138, 180, 248, 0.1);
            border-left: 4px solid #8ab4f8;
            border-radius: 4px;
            padding: 16px;
            margin: 20px 0;
        }}
        .warning {{
            background: rgba(242, 139, 130, 0.1);
            border-left: 4px solid #f28b82;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 New Sign-In Detected</h1>
        <p>Hello {user.full_name},</p>
        <p>We detected a new sign-in to your JoshAtticusID account.</p>
        <div class="info-box">
            <p><strong>Device:</strong> {device_info}</p>
            <p><strong>Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Location:</strong> {location}</p>
        </div>
        <p>If this was you, you can safely ignore this email.</p>
        <div class="warning">
            <p><strong>⚠️ Didn't recognize this sign-in?</strong></p>
            <p>Please secure your account immediately by changing your password.</p>
        </div>
        <div class="footer">
            <small>You are recieving this email because someone signed into your JoshAtticusID account from a device or location we don't recognize.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(user.email, "New Sign-In to Your JoshAtticusID Account", text_content, html_content)


def send_oauth_authorization_email(user, app_name):
    """Send email notification for new OAuth app authorization"""
    text_content = f"""
Hello {user.full_name},

You have authorized a new application to access your JoshAtticusID account.

Application: {app_name}
Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

You can manage your authorized applications anytime from your dashboard.

If you didn't authorize this application, please revoke its access immediately.

You are recieving this email because you authorized a new application to access your JoshAtticusID account.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #8ab4f8;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .info-box {{
            background: rgba(138, 180, 248, 0.1);
            border-left: 4px solid #8ab4f8;
            border-radius: 4px;
            padding: 16px;
            margin: 20px 0;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔗 New App Authorized</h1>
        <p>Hello {user.full_name},</p>
        <p>You have authorized a new application to access your JoshAtticusID account.</p>
        <div class="info-box">
            <p><strong>Application:</strong> {app_name}</p>
            <p><strong>Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        <p>You can manage your authorized applications anytime from your dashboard.</p>
        <p>If you didn't authorize this application, please revoke its access immediately.</p>
        <div class="footer">
            <small>You are recieving this email because you authorized a new application to access your JoshAtticusID account.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(user.email, f"New App Authorized: {app_name}", text_content, html_content)


def send_app_banned_email(owner_email, app_name, reason):
    """Send email to app owner when their app is banned"""
    text_content = f"""
Hello,

Your OAuth application "{app_name}" has been banned.

Reason: {reason}

All user authorizations for this application have been revoked and the app can no longer be used.

If you believe this was done in error, please reply to this email.

You are recieving this email because your app has violated our Terms of Service or Privacy Policy.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #f28b82;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .warning {{
            background: rgba(242, 139, 130, 0.1);
            border-left: 4px solid #f28b82;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Application Banned</h1>
        <p>Hello,</p>
        <p>Your OAuth application <strong>"{app_name}"</strong> has been banned.</p>
        <div class="warning">
            <p><strong>Reason:</strong></p>
            <p>{reason}</p>
        </div>
        <p>All user authorizations for this application have been revoked and the app can no longer be used.</p>
        <p>If you believe this was done in error, please reply to this email.</p>
        <div class="footer">
            <small>You are recieving this email because your app has violated our Terms of Service or Privacy Policy.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(owner_email, f"Your App '{app_name}' Has Been Banned", text_content, html_content)


def send_app_verified_email(owner_email, app_name):
    """Send email to app owner when their app is verified"""
    text_content = f"""
Hello,

Congratulations! Your OAuth application "{app_name}" has been verified!

Your app will now display a verified badge when users sign in.

You are recieving this email because we have verified an OAuth Application created by you.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #81c995;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .success {{
            background: rgba(129, 201, 149, 0.1);
            border-left: 4px solid #81c995;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Application Verified</h1>
        <p>Hello,</p>
        <p>Congratulations! Your OAuth application <strong>"{app_name}"</strong> has been verified!</p>
        <div class="success">
            <p>✓ Your app is now verified and will display a verified badge when users sign in.</p>
        </div>
        <div class="footer">
            <small>You are recieving this email because we have verified an OAuth Application created by you.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(owner_email, f"Your App '{app_name}' Is Now Verified!", text_content, html_content)


def send_app_unverified_email(owner_email, app_name, reason):
    """Send email to app owner when their app verification is removed"""
    text_content = f"""
Hello,

Your OAuth application "{app_name}" verification has been removed.

Reason: {reason}

Your app will no longer display a verified badge.

If you believe this was done in error, please reply to this email.

You are recieving this email because your app verification status has changed.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #fdd663;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .warning {{
            background: rgba(253, 214, 99, 0.1);
            border-left: 4px solid #fdd663;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Verification Removed</h1>
        <p>Hello,</p>
        <p>Your OAuth application <strong>"{app_name}"</strong> is no longer verified.</p>
        <div class="warning">
            <p><strong>Reason:</strong></p>
            <p>{reason}</p>
        </div>
        <p>Your app will no longer display a verified badge.</p>
        <p>If you believe this was done in error, please reply to this email.</p>
        <div class="footer">
            <small>You are recieving this email because your app verification status has changed.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(owner_email, f"Verification Removed: {app_name}", text_content, html_content)


def send_welcome_email(user):
    """Send welcome email to new users"""
    text_content = f"""
Hello {user.full_name},

Welcome to JoshAtticusID!

Your account has been successfully created and verified. You can now use your JoshAtticusID account to sign in to apps and services that support it.

You are recieving this email because you signed up for a JoshAtticusID account. If this was not you, please reply to this email and let us know.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #8ab4f8;
            font-size: 28px;
            margin-bottom: 20px;
        }}
        .welcome-box {{
            background: rgba(138, 180, 248, 0.1);
            border-left: 4px solid #8ab4f8;
            border-radius: 4px;
            padding: 20px;
            margin: 24px 0;
        }}
        .features {{
            margin: 24px 0;
        }}
        .feature-item {{
            padding: 12px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .feature-item:last-child {{
            border-bottom: none;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 Welcome to JoshAtticusID!</h1>
        <p>Hello {user.full_name},</p>
        <div class="welcome-box">
            <p><strong>Your account has been successfully created and verified!</strong></p>
            <p>You can now use your JoshAtticusID account to sign in to apps and services.</p>
        </div>
        <p>If you have any questions, feel free to reply to this email.</p>
        <div class="footer">
            <small>You are recieving this email because you signed up for a JoshAtticusID account. If this was not you, please reply to this email and let us know.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(user.email, "Welcome to JoshAtticusID! 🎉", text_content, html_content)


def send_password_reset_email(email, code):
    """Send password reset email with verification code"""
    text_content = f"""
Hello,

You requested to reset your password for your JoshAtticusID account.

Your password reset code is: {code}

This code will expire in 15 minutes.

If you didn't request this password reset, please ignore this email and ensure your account is secure.

You are recieving this email because you requested a password reset for your JoshAtticusID account. If this was not you, please ignore this email and ensure your account is secure.
"""

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Inter', 'Google Sans', Arial, sans-serif;
            background: linear-gradient(135deg, rgb(10, 10, 10) 0%, rgb(30, 30, 30) 100%);
            color: #e8eaed;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: rgba(45, 46, 48, 0.6);
            border-radius: 12px;
            padding: 32px;
            backdrop-filter: blur(10px);
        }}
        h1 {{
            color: #8ab4f8;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .code {{
            background: rgba(138, 180, 248, 0.1);
            border: 2px solid #8ab4f8;
            border-radius: 8px;
            padding: 24px;
            text-align: center;
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #8ab4f8;
            margin: 24px 0;
        }}
        .warning {{
            background: rgba(242, 139, 130, 0.1);
            border-left: 4px solid #f28b82;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        p {{
            line-height: 1.6;
            color: #e8eaed;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #969ba1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Password Reset Request</h1>
        <p>You requested to reset your password for your JoshAtticusID account.</p>
        <p>Your password reset code is:</p>
        <div class="code">{code}</div>
        <p>This code will expire in 15 minutes.</p>
        <div class="warning">
            <p><strong>⚠️ Didn't request this?</strong></p>
            <p>If you didn't request this password reset, please ignore this email and ensure your account is secure.</p>
        </div>
        <div class="footer">
            <small>You are recieving this email because you requested a password reset for your JoshAtticusID account. If this was not you, please ignore this email and ensure your account is secure.</small>
        </div>
    </div>
</body>
</html>
"""
    
    send_email(email, "Password Reset Code - JoshAtticusID", text_content, html_content)


def generate_verification_code():
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def validate_file_upload(file):
    if not file or not file.filename:
        return False, "No file provided"
    
    allowed_extensions = {'png', 'jpg', 'jpeg'}
    filename = file.filename.lower()
    
    if not any(filename.endswith('.' + ext) for ext in allowed_extensions):
        return False, "Invalid file type"
    
    magic_numbers = {
        b'\x89PNG\r\n\x1a\n': 'png',
        b'\xff\xd8\xff': 'jpeg'
    }
    
    file.seek(0)
    header = file.read(8)
    file.seek(0)
    
    valid = False
    for magic, ftype in magic_numbers.items():
        if header.startswith(magic):
            valid = True
            break
    
    if not valid:
        return False, "File content does not match extension"
    
    return True, "Valid file"

@app.route("/account/create", methods=["POST"])
def create_account():
    data = request.get_json()
    password = data.get("password")
    full_name = data.get("full_name")
    dob = data.get("dob")
    email = data.get("email")
    verification_code = data.get("verification_code")

    if not email or "@" not in email or len(email) > 100:
        return jsonify({"message": "Invalid email format"}), 400

    if not all([password, full_name, dob, verification_code]):
        return jsonify({"message": "Missing required fields"}), 400
    
    if len(full_name) > 100:
        return jsonify({"message": "Name is too long"}), 400

    valid, msg = validate_password_strength(password)
    if not valid:
        return jsonify({"message": msg}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 409

    verification = EmailVerification.query.filter_by(
        email=email,
        code=verification_code,
        verified=False
    ).first()

    if not verification:
        return jsonify({"message": "Invalid verification code"}), 400

    if datetime.now(timezone.utc) > verification.expires_at.replace(tzinfo=timezone.utc):
        return jsonify({"message": "Verification code has expired"}), 400

    try:
        dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
        
        today = datetime.now().date()
        age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
        if age < 13:
            return jsonify({"message": "You must be at least 13 years old to sign up."}), 400

        # Check if this is the first user (make them admin)
        user_count = User.query.count()
        is_first_user = user_count == 0

        new_user = User(
            full_name=full_name,
            dob=dob_date,
            email=email,
            email_verified=True,
            is_admin=is_first_user
        )
        new_user.set_password(password)
        
        verification.verified = True
        
        db.session.add(new_user)
        db.session.commit()
        
        # Send welcome email
        send_welcome_email(new_user)
        
        # Auto-login: Generate JWT token for the new user
        token = jwt.encode(
            {
                "user_id": new_user.id,
                "exp": datetime.now(timezone.utc) + timedelta(hours=2)
            },
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        
        return jsonify({
            "message": "Account created successfully",
            "token": token
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating account"}), 500


@app.route("/account/send-verification", methods=["POST"])
def send_verification():
    data = request.get_json()
    email = data.get("email")

    if not email or "@" not in email or len(email) > 100:
        return jsonify({"message": "Invalid email format"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 409

    code = generate_verification_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    existing = EmailVerification.query.filter_by(email=email, verified=False).first()
    if existing:
        existing.code = code
        existing.expires_at = expires_at
        existing.created_at = datetime.now(timezone.utc)
    else:
        verification = EmailVerification(
            email=email,
            code=code,
            expires_at=expires_at
        )
        db.session.add(verification)

    try:
        db.session.commit()
        
        if send_verification_email(email, code):
            return jsonify({"message": "Verification code sent"}), 200
        else:
            return jsonify({"message": "Error sending verification email"}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error processing request"}), 500


@app.route("/account/check-verification", methods=["POST"])
def check_verification():
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")

    if not email or not code:
        return jsonify({"valid": False, "message": "Missing email or code"}), 400

    if len(code) != 6:
        return jsonify({"valid": False, "message": "Code must be 6 digits"}), 400

    verification = EmailVerification.query.filter_by(
        email=email,
        code=code,
        verified=False
    ).first()

    if not verification:
        return jsonify({"valid": False, "message": "Invalid verification code"}), 400

    if datetime.now(timezone.utc) > verification.expires_at.replace(tzinfo=timezone.utc):
        return jsonify({"valid": False, "message": "Verification code has expired"}), 400

    return jsonify({"valid": True, "message": "Code is valid"}), 200


@app.route("/account/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    remember_me = data.get("remember_me", False)

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        current_time = datetime.now(timezone.utc)  # Get current UTC time
        
        # Default to 24 hours, extend to 30 days if remember_me is True
        expiration_delta = timedelta(days=30) if remember_me else timedelta(hours=24)

        token = jwt.encode(
            {"user_id": user.id, "exp": current_time + expiration_delta},
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
        return jsonify({
            "token": token,
            "user": {
                "full_name": user.full_name,
                "email": user.email
            }
        })

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/account/password-reset/request", methods=["POST"])
def request_password_reset():
    """Request a password reset code"""
    data = request.get_json()
    email = data.get("email")

    if not email or "@" not in email or len(email) > 100:
        return jsonify({"message": "Invalid email format"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if user exists or not for security
        return jsonify({"message": "If an account exists with this email, a reset code has been sent"}), 200

    # Generate reset code
    code = generate_verification_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    # Check for existing unused reset request
    existing = PasswordReset.query.filter_by(email=email, used=False).first()
    if existing:
        existing.code = code
        existing.expires_at = expires_at
        existing.created_at = datetime.now(timezone.utc)
    else:
        reset_request = PasswordReset(
            email=email,
            code=code,
            expires_at=expires_at
        )
        db.session.add(reset_request)

    try:
        db.session.commit()
        
        if send_password_reset_email(email, code):
            return jsonify({"message": "If an account exists with this email, a reset code has been sent"}), 200
        else:
            return jsonify({"message": "Error sending reset email"}), 500
    except Exception as e:
        db.session.rollback()
        print(f"Error in password reset request: {str(e)}")
        return jsonify({"message": "Error processing request"}), 500


@app.route("/account/password-reset/verify", methods=["POST"])
def verify_password_reset():
    """Verify the password reset code"""
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")

    if not email or not code:
        return jsonify({"valid": False, "message": "Missing email or code"}), 400

    if len(code) != 6:
        return jsonify({"valid": False, "message": "Code must be 6 digits"}), 400

    reset_request = PasswordReset.query.filter_by(
        email=email,
        code=code,
        used=False
    ).first()

    if not reset_request:
        return jsonify({"valid": False, "message": "Invalid reset code"}), 400

    if datetime.now(timezone.utc) > reset_request.expires_at.replace(tzinfo=timezone.utc):
        return jsonify({"valid": False, "message": "Reset code has expired"}), 400

    return jsonify({"valid": True, "message": "Code is valid"}), 200


@app.route("/account/password-reset/complete", methods=["POST"])
def complete_password_reset():
    """Complete the password reset with new password"""
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("new_password")

    if not all([email, code, new_password]):
        return jsonify({"message": "Missing required fields"}), 400

    # Validate password strength
    valid, msg = validate_password_strength(new_password)
    if not valid:
        return jsonify({"message": msg}), 400

    # Find the reset request
    reset_request = PasswordReset.query.filter_by(
        email=email,
        code=code,
        used=False
    ).first()

    if not reset_request:
        return jsonify({"message": "Invalid reset code"}), 400

    if datetime.now(timezone.utc) > reset_request.expires_at.replace(tzinfo=timezone.utc):
        return jsonify({"message": "Reset code has expired"}), 400

    # Find user and update password
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    try:
        user.set_password(new_password)
        reset_request.used = True
        
        # End all existing sessions for security
        Session.query.filter_by(user_id=user.id).delete()
        
        db.session.commit()
        
        return jsonify({"message": "Password reset successfully"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error completing password reset: {str(e)}")
        return jsonify({"message": "Error resetting password"}), 500


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
                "email_verified": user.email_verified,
            }
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        print(f"Error in get_user_details: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500


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

        valid, msg = validate_file_upload(file)
        if not valid:
            return jsonify({"message": msg}), 400

        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"{user.id}_{secrets.token_hex(8)}.{ext}")
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        if user.profile_picture:
            old_file = os.path.join(app.config["UPLOAD_FOLDER"], user.profile_picture)
            if os.path.exists(old_file):
                os.remove(old_file)

        file.save(filepath)
        user.profile_picture = filename
        db.session.commit()

        return jsonify({"message": "Profile picture updated", "filename": filename})

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"message": "Error uploading file"}), 500


@app.route("/account/recommendations", methods=["GET"])
def get_recommendations():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    session = Session.query.filter_by(token=token).first()
    if not session:
        return jsonify({"error": "Invalid token"}), 401

    user = User.query.get(session.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    recommendations = []
    
    if not user.has_accepted_legal:
        recommendations.append({
            'title': 'Review our updated terms',
            'description': 'We\'ve updated our Privacy Policy and Terms of Service. Please take a moment to review them.',
            'action': 'redirect',
            'action_url': '/legal'
        })

    # Placeholder for other recommendations
    # Example: recommendations.append({'title': 'Enable 2FA', 'description': 'Add an extra layer of security to your account'})

    return jsonify(recommendations)


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
        
        if not state or len(state) < 8:
            return jsonify({
                "error": "invalid_request",
                "error_description": "State parameter is required for security"
            }), 400

        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({
                "error": "invalid_client",
                "error_description": "No application found with this client ID"
            }), 400
        
        if oauth_app.banned:
            return jsonify({
                "error": "access_denied",
                "error_description": "This app has been banned and cannot be used. If you are a user, do not continue using this app. If you are the app developer, please send an email to id@joshattic.us to appeal this ban."
            }), 403
        
        # Validate redirect URI against registered URIs (comma-separated list)
        try:
            registered_uris = [uri.strip() for uri in oauth_app.redirect_uri.split(',')]
            request_uri = urlparse(redirect_uri)
            
            valid_uri = False
            for registered in registered_uris:
                reg_parsed = urlparse(registered)
                if (reg_parsed.scheme == request_uri.scheme and
                    reg_parsed.netloc == request_uri.netloc and
                    (not reg_parsed.path or request_uri.path.startswith(reg_parsed.path))):
                    valid_uri = True
                    break
            
            if not valid_uri:
                return jsonify({
                    "error": "invalid_redirect_uri",
                    "error_description": f"The redirect URI must match one of the registered URIs. Got: {redirect_uri}"
                }), 400
        except ValueError:
            return jsonify({"error": "invalid_redirect_uri", "error_description": "Malformed redirect URI"}), 400

        requested_scopes = scope.split()
        if not all(s in OAUTH_SCOPES for s in requested_scopes):
            return jsonify({
                "error": "invalid_scope",
                "error_description": f"Invalid scopes: {[s for s in requested_scopes if s not in OAUTH_SCOPES]}"
            }), 400

        return send_from_directory("static", "authorize.html")

    token = request.headers.get("Authorization") or request.form.get("token")
    if not token:
        return jsonify({"error": "invalid_request", "error_description": "Token is missing"}), 401
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        if not user:
            return jsonify({"error": "invalid_request", "error_description": "User not found"}), 404
        
        if request.is_json:
            client_id = request.json.get("client_id")
            scope = request.json.get("scope", "")
            redirect_uri = request.json.get("redirect_uri")
            state = request.json.get("state")
        else:
            client_id = request.form.get("client_id")
            scope = request.form.get("scope", "")
            redirect_uri = request.form.get("redirect_uri")
            state = request.form.get("state")
        
        if not state or len(state) < 8:
            return jsonify({"error": "invalid_request", "error_description": "State parameter is required"}), 400
        
        oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
        if not oauth_app:
            return jsonify({"error": "invalid_client"}), 400
        
        # Validate redirect URI against registered URIs (comma-separated list)
        try:
            registered_uris = [uri.strip() for uri in oauth_app.redirect_uri.split(',')]
            request_uri = urlparse(redirect_uri)
            
            valid_uri = False
            for registered in registered_uris:
                reg_parsed = urlparse(registered)
                if (reg_parsed.scheme == request_uri.scheme and
                    reg_parsed.netloc == request_uri.netloc and
                    (not reg_parsed.path or request_uri.path.startswith(reg_parsed.path))):
                    valid_uri = True
                    break
            
            if not valid_uri:
                return jsonify({"error": "invalid_redirect_uri"}), 400
        except ValueError:
            return jsonify({"error": "invalid_redirect_uri"}), 400
        requested_scopes = scope.split()
        if not all(s in OAUTH_SCOPES for s in requested_scopes):
            return jsonify({"error": "invalid_scope"}), 400
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

@app.route("/oauth/check-authorization", methods=["GET"])
def check_authorization():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "missing_token"}), 401
        
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = data["user_id"]
    except:
        return jsonify({"error": "invalid_token"}), 401

    client_id = request.args.get("client_id")
    requested_scopes = request.args.get("scope", "").split()
    
    if not client_id:
        return jsonify({"error": "missing_client_id"}), 400
        
    oauth_app = OAuthApp.query.filter_by(client_id=client_id).first()
    if not oauth_app:
        return jsonify({"error": "invalid_client"}), 404
        
    auth = OAuthAuthorization.query.filter_by(user_id=user_id, app_id=oauth_app.id).first()
    
    if not auth:
        return jsonify({
            "authorized": False,
            "requires_consent": True
        })
        
    # Check scopes
    existing_scopes = auth.scopes.split()
    missing_scopes = [s for s in requested_scopes if s not in existing_scopes]
    
    # Logic: Show consent if missing scopes OR usage_count % 4 == 0 (meaning this is the 4th, 8th, etc. time)
    # We check (usage_count + 1) because usage_count will be incremented after this flow completes
    requires_consent = bool(missing_scopes) or ((auth.usage_count + 1) % 4 == 0)
    
    return jsonify({
        "authorized": True,
        "requires_consent": requires_consent,
        "usage_count": auth.usage_count,
        "missing_scopes": missing_scopes
    })

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
        
        # Validate redirect URI against registered URIs (comma-separated list)
        try:
            registered_uris = [uri.strip() for uri in oauth_app.redirect_uri.split(',')]
            request_uri = urlparse(redirect_uri)
            
            valid_uri = False
            for registered in registered_uris:
                reg_parsed = urlparse(registered)
                if (reg_parsed.scheme == request_uri.scheme and
                    reg_parsed.netloc == request_uri.netloc and
                    (not reg_parsed.path or request_uri.path.startswith(reg_parsed.path))):
                    valid_uri = True
                    break
            
            if not valid_uri:
                return jsonify({
                    "error": "invalid_redirect_uri",
                    "details": "The redirect URI must match one of the registered URIs"
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
            
            # Send email notification for new authorization (not for re-login)
            send_oauth_authorization_email(user, oauth_app.name)

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
            access_token=access_token,
            usage_count=1
        )
        db.session.add(auth)
    else:
        auth.scopes = oauth_code.scopes
        auth.access_token = access_token
        auth.usage_count = (auth.usage_count or 0) + 1
        auth.last_used = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": oauth_code.scopes,
    })


@app.route("/oauth/token/revoke", methods=["POST"])
def oauth_revoke():
    token = request.form.get("token")
    token_type_hint = request.form.get("token_type_hint", "access_token")
    
    if not token:
        return jsonify({"error": "invalid_request"}), 400
    
    auth = OAuthAuthorization.query.filter_by(access_token=token).first()
    if auth:
        db.session.delete(auth)
        db.session.commit()
    
    return '', 200


@app.route("/oauth/token/introspect", methods=["POST"])
def oauth_introspect():
    token = request.form.get("token")
    
    if not token:
        return jsonify({"active": False}), 200
    
    auth = OAuthAuthorization.query.filter_by(access_token=token).first()
    
    if not auth:
        return jsonify({"active": False}), 200
    
    user = User.query.get(auth.user_id)
    app = OAuthApp.query.get(auth.app_id)
    
    if not user or not app:
        return jsonify({"active": False}), 200
    
    return jsonify({
        "active": True,
        "scope": auth.scopes,
        "client_id": app.client_id,
        "username": user.email,
        "token_type": "Bearer",
        "sub": str(user.id)
    })

@app.route("/oauth/userinfo", methods=["GET", "POST"])
def oauth_userinfo():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401
    access_token = auth_header.split(" ")[1]
    auth = OAuthAuthorization.query.filter_by(access_token=access_token).first()
    if not auth:
        return jsonify({"error": "invalid_token"}), 401
    
    auth.last_used = datetime.now(timezone.utc)
    db.session.commit()
    
    user = User.query.get(auth.user_id)
    scopes = auth.scopes.split()
    response = {
        "sub": str(user.id)
    }
    if "name" in scopes:
        response["name"] = user.full_name
    if "dob" in scopes:
        response["birthdate"] = user.dob.strftime("%Y-%m-%d")
    if "email" in scopes:
        response["email"] = user.email
        response["email_verified"] = True
    if "profile_picture" in scopes:
        if user.profile_picture:
            response["picture"] = f"https://id.joshattic.us/static/uploads/{user.profile_picture}"
        else:
            response["picture"] = "https://id.joshattic.us/static/uploads/default.png"
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
        auth_id = request.json.get("app_id")  # This is actually the authorization ID

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Look up authorization by ID and verify it belongs to the user
        auth = OAuthAuthorization.query.filter_by(
            id=auth_id, user_id=user.id
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

        valid, msg = validate_password_strength(password)
        
        return jsonify({
            'is_strong': valid,
            'message': msg
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
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
        
        valid, msg = validate_password_strength(new_password)
        if not valid:
            return jsonify({'message': msg}), 400
            
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password updated successfully'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception:
        return jsonify({'message': 'Error changing password'}), 500

@app.route('/account/accept-legal', methods=['POST'])
def accept_legal():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401

    session = Session.query.filter_by(token=token).first()
    if not session:
        return jsonify({'error': 'Invalid token'}), 401

    user = User.query.get(session.user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.has_accepted_legal = True
    db.session.commit()

    return jsonify({'message': 'Legal terms accepted'}), 200


@app.route('/account/update-profile', methods=['POST'])
def update_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        request_data = request.json
        full_name = request_data.get('full_name')
        dob = request_data.get('dob')
        
        if full_name:
            if len(full_name) > 100:
                return jsonify({'message': 'Name is too long'}), 400
            user.full_name = full_name
        
        if dob:
            try:
                dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
                today = datetime.now().date()
                age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
                if age < 13:
                    return jsonify({'message': 'You must be at least 13 years old'}), 400
                user.dob = dob_date
            except ValueError:
                return jsonify({'message': 'Invalid date format'}), 400
        
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})
        
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        db.session.rollback()
        print(f"Error updating profile: {str(e)}")
        return jsonify({'message': 'Error updating profile'}), 500


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


# Admin endpoints
@app.route("/admin")
def admin_panel():
    return send_from_directory("static", "admin.html")


@app.route("/admin/apps", methods=["GET"])
def admin_list_all_apps():
    """Admin endpoint to list all OAuth apps with pagination"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized - Admin access required"}), 403

        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Limit per_page to reasonable values
        per_page = min(per_page, 100)
        
        # Query with pagination
        pagination = OAuthApp.query.order_by(OAuthApp.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        apps_list = []
        for oauth_app in pagination.items:
            owner = User.query.get(oauth_app.user_id)
            apps_list.append({
                "id": oauth_app.id,
                "name": oauth_app.name,
                "client_id": oauth_app.client_id,
                "redirect_uri": oauth_app.redirect_uri,
                "website": oauth_app.website,
                "verified": oauth_app.verified,
                "banned": oauth_app.banned,
                "created_at": oauth_app.created_at.isoformat(),
                "owner_email": owner.email if owner else "Unknown",
                "owner_name": owner.full_name if owner else "Unknown"
            })
        
        return jsonify({
            "apps": apps_list,
            "total": pagination.total,
            "page": pagination.page,
            "per_page": pagination.per_page,
            "pages": pagination.pages,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/admin/apps/<app_id>/verify", methods=["POST"])
def admin_verify_app(app_id):
    """Admin endpoint to verify an OAuth app"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized - Admin access required"}), 403

        oauth_app = OAuthApp.query.get(app_id)
        if not oauth_app:
            return jsonify({"message": "App not found"}), 404

        oauth_app.verified = True
        db.session.commit()
        
        # Send email notification to app owner
        owner = User.query.get(oauth_app.user_id)
        if owner:
            send_app_verified_email(owner.email, oauth_app.name)
        
        return jsonify({"message": "App verified successfully"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/admin/apps/<app_id>/unverify", methods=["POST"])
def admin_unverify_app(app_id):
    """Admin endpoint to unverify an OAuth app"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized - Admin access required"}), 403

        oauth_app = OAuthApp.query.get(app_id)
        if not oauth_app:
            return jsonify({"message": "App not found"}), 404

        # Get reason from request body
        request_data = request.get_json() or {}
        reason = request_data.get("reason", "No reason provided")

        oauth_app.verified = False
        db.session.commit()
        
        # Send email notification to app owner
        owner = User.query.get(oauth_app.user_id)
        if owner:
            send_app_unverified_email(owner.email, oauth_app.name, reason)
        
        return jsonify({"message": "App unverified successfully"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/admin/apps/<app_id>/ban", methods=["POST"])
def admin_ban_app(app_id):
    """Admin endpoint to ban an OAuth app"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized - Admin access required"}), 403

        oauth_app = OAuthApp.query.get(app_id)
        if not oauth_app:
            return jsonify({"message": "App not found"}), 404

        # Get reason from request body
        request_data = request.get_json() or {}
        reason = request_data.get("reason", "No reason provided")

        oauth_app.banned = True
        
        # Revoke all authorizations for this app
        authorizations = OAuthAuthorization.query.filter_by(app_id=app_id).all()
        for auth in authorizations:
            db.session.delete(auth)
        
        db.session.commit()
        
        # Send email notification to app owner
        owner = User.query.get(oauth_app.user_id)
        if owner:
            send_app_banned_email(owner.email, oauth_app.name, reason)
        
        return jsonify({"message": "App banned successfully", "revoked_count": len(authorizations)}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/admin/apps/<app_id>/unban", methods=["POST"])
def admin_unban_app(app_id):
    """Admin endpoint to unban an OAuth app"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized - Admin access required"}), 403

        oauth_app = OAuthApp.query.get(app_id)
        if not oauth_app:
            return jsonify({"message": "App not found"}), 404

        oauth_app.banned = False
        db.session.commit()
        
        return jsonify({"message": "App unbanned successfully"}), 200
        db.session.commit()
        
        return jsonify({"message": "App unbanned successfully"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/admin/apps/<app_id>", methods=["PUT"])
def admin_edit_app(app_id):
    """Admin endpoint to edit any OAuth app"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized - Admin access required"}), 403

        oauth_app = OAuthApp.query.get(app_id)
        if not oauth_app:
            return jsonify({"message": "App not found"}), 404

        update_data = request.get_json()
        
        if "name" in update_data:
            oauth_app.name = update_data["name"]
        if "redirect_uri" in update_data:
            oauth_app.redirect_uri = update_data["redirect_uri"]
        if "website" in update_data:
            oauth_app.website = update_data["website"]
        
        db.session.commit()
        
        return jsonify({"message": "App updated successfully"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route("/account/is-admin", methods=["GET"])
def check_is_admin():
    """Check if the current user is an admin"""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"is_admin": False}), 200

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = User.query.get(data["user_id"])
        
        return jsonify({"is_admin": user.is_admin if user else False}), 200
    except:
        return jsonify({"is_admin": False}), 200


@app.route("/developer")
def developer_dashboard():
    return send_from_directory("static", "developer.html")


@app.route("/authorize")
def authorize_oauth_app():
    return send_from_directory("static", "authorize.html")


@app.route("/legal")
def legal():
    return send_from_directory("static", "legal.html")


@app.route("/privacy")
def privacy():
    return redirect('/legal')


@app.route("/terms")
def terms():
    return redirect('/legal')


# Create the database tables
def init_db():
    with app.app_context():
        db.create_all()
        
        # After creating tables, check if we need to perform migrations
        perform_migrations()

def perform_migrations():
    """Check for and apply any needed database migrations."""
    with app.app_context():
        try:
            # Use engine.begin() to get a connection and start a single transaction.
            # It automatically commits on success or rolls back on error.
            with db.engine.begin() as connection:
                # --- Migration 1: Add user_id to oauth_app ---
                # The .all() is important to consume the result before the next query
                oauth_app_cols = connection.execute(text("PRAGMA table_info(oauth_app)")).all()
                if not any(col[1] == 'user_id' for col in oauth_app_cols):
                    print("Migrating database: Adding user_id column to oauth_app table...")
                    connection.execute(text("ALTER TABLE oauth_app ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1"))
                    print("Migration complete: oauth_app.user_id added.")

                # --- Migration 2: Add has_accepted_legal to user ---
                user_cols = connection.execute(text("PRAGMA table_info(user)")).all()
                if not any(col[1] == 'has_accepted_legal' for col in user_cols):
                    print("Migrating database: Adding has_accepted_legal column to user table...")
                    connection.execute(text("ALTER TABLE user ADD COLUMN has_accepted_legal BOOLEAN NOT NULL DEFAULT 0"))
                    print("Migration complete: user.has_accepted_legal added.")

                # --- Migration 3: Add email_verified to user ---
                user_cols = connection.execute(text("PRAGMA table_info(user)")).all()
                if not any(col[1] == 'email_verified' for col in user_cols):
                    print("Migrating database: Adding email_verified column to user table...")
                    connection.execute(text("ALTER TABLE user ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0"))
                    print("Migration complete: user.email_verified added.")

                # --- Migration 4: Add is_admin to user ---
                user_cols = connection.execute(text("PRAGMA table_info(user)")).all()
                if not any(col[1] == 'is_admin' for col in user_cols):
                    print("Migrating database: Adding is_admin column to user table...")
                    connection.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0"))
                    # Make the first user an admin if exists
                    first_user = connection.execute(text("SELECT id FROM user ORDER BY id LIMIT 1")).first()
                    if first_user:
                        connection.execute(text("UPDATE user SET is_admin = 1 WHERE id = :id"), {"id": first_user[0]})
                    print("Migration complete: user.is_admin added.")

                # --- Migration 5: Add banned to oauth_app ---
                oauth_app_cols = connection.execute(text("PRAGMA table_info(oauth_app)")).all()
                if not any(col[1] == 'banned' for col in oauth_app_cols):
                    print("Migrating database: Adding banned column to oauth_app table...")
                    connection.execute(text("ALTER TABLE oauth_app ADD COLUMN banned BOOLEAN NOT NULL DEFAULT 0"))
                    print("Migration complete: oauth_app.banned added.")

        except Exception as e:
            print(f"Error during database migration: {str(e)}")


# Initialize database on app startup (works with both gunicorn and direct run)
try:
    init_db()
    print("✅ Database initialized successfully")
except Exception as e:
    print(f"⚠️  Database initialization warning: {str(e)}")


if __name__ == "__main__":
    print("\033[91mYOU ARE RUNNING THE SERVER IN DEBUG MODE! DO NOT USE THIS IN PRODUCTION!\033[0m")
    app.run(debug=True, port=5002)
# GitHub Copilot Instructions for JoshAtticusID

## Project Overview
JoshAtticusID is an OAuth 2.0 identity provider built with Flask. It handles user authentication, profile management, OAuth app authorization, and email verification with a focus on security and user experience.

## Security Guidelines

### Input Validation & Sanitization
- **NEVER** directly inject user input into HTML without sanitization
- Always use `escapeHtml()` function from `/static/security.js` for text content
- Use `sanitizeUrl()` for all URLs before setting as href or src attributes
- Use `validateRedirect()` for all redirect operations to prevent open redirect attacks
- Validate all user inputs on both client and server side
- Enforce length limits on all text inputs (e.g., email: 100 chars, name: 100 chars)
- Use parameterized queries or ORM methods only - never concatenate SQL

### XSS Prevention
- Use `textContent` instead of `innerHTML` when inserting user data
- Use `createElement()` and `appendChild()` instead of template strings with user data
- If HTML rendering is required, sanitize with DOMPurify or similar library
- Avoid inline event handlers (onclick, onerror, etc.) in HTML
- Use addEventListener for event binding

### Authentication & Authorization
- JWT tokens expire after 2 hours maximum
- Store sensitive tokens in localStorage only, never in cookies without HttpOnly flag
- Always verify tokens on server side before processing requests
- Use cryptographically secure random values for all secrets and tokens
- Never hardcode SECRET_KEY - always use environment variables
- Implement proper session management with activity tracking

### Password Security
- Minimum password length: 8 characters
- Require: uppercase, lowercase, number
- Check against common password lists
- Use werkzeug's password hashing (PBKDF2)
- Never log or expose passwords
- Implement password strength validation server-side

### File Upload Security
- Validate file content (magic numbers), not just extensions
- Use secure_filename() for all uploaded filenames
- Add random tokens to filenames to prevent overwrites
- Limit file sizes (5MB maximum)
- Store uploads outside webroot when possible
- Only allow specific MIME types (PNG, JPEG for profile pictures)

### OAuth Security
- Always require and validate state parameter (minimum 8 characters)
- Implement PKCE for public clients
- Validate redirect URIs against registered values
- Authorization codes expire after 10 minutes
- Codes are single-use only
- Scope validation on every request
- Support OAuth 2.0 token revocation (RFC 7009)
- Support OAuth 2.0 token introspection (RFC 7662)
- Provide OpenID Connect Discovery endpoint
- Use standard OAuth2/OIDC claim names (sub, email_verified, picture, birthdate)

### Email Verification
- Users must verify email with 6-digit code during signup
- Verification codes expire after 15 minutes
- Use cryptographically secure random number generation for codes
- Send emails via SMTP (configured in environment variables)
- Mark verification codes as used after successful verification
- Store email_verified flag in User model
- Support resending verification codes
- HTML and plain text email templates for compatibility
- Never expose SMTP credentials in code or logs

### API Security
- Add security headers to all responses (CSP, X-Frame-Options, etc.)
- Implement rate limiting on authentication endpoints
- Return generic error messages to prevent information disclosure
- Log security events for monitoring
- Use HTTPS only in production
- Validate Content-Type headers

### Data Protection
- Never expose internal IDs unnecessarily
- Sanitize error messages before sending to client
- Don't leak user existence through different error messages
- Implement proper CORS policies
- Use secure session cookies (HttpOnly, Secure, SameSite)

## Design Guidelines

### UI/UX Principles
- Dark theme with Material Design-inspired aesthetics
- Primary color: #8ab4f8 (light blue)
- Smooth transitions and animations (0.3s default)
- Glassmorphism effects with backdrop-blur
- Card-based layouts with consistent spacing (24px standard)
- Responsive design with mobile-first approach

### Color Palette
```css
--background-start-rgb: 10, 10, 10
--background-end-rgb: 30, 30, 30
--tile-start-rgb: 45, 46, 48
--tile-end-rgb: 32, 33, 36
--primary-color: #8ab4f8
--secondary-color: #969ba1
--text-color: #e8eaed
--danger-color: #f28b82
```

### Typography
- Font: Inter (Google Fonts)
- Fallback: 'Google Sans', 'Noto Sans Myanmar UI', Arial, sans-serif
- Base size: 16px
- Headers: 22px-28px
- Small text: 12-14px

### Component Patterns
- Use consistent border-radius: 8px for buttons, 12px for cards
- Box shadows: `0 8px 32px 0 rgba(0, 0, 0, 0.37)` for cards
- Hover effects: slight elevation (translateY(-2px)) with shadow
- Input focus: border glow with box-shadow
- Loading states should show visual feedback
- Error states use --danger-color with shake animation

### Accessibility
- Maintain WCAG 2.1 AA contrast ratios
- Provide keyboard navigation support
- Use semantic HTML elements
- Include ARIA labels where needed
- Support screen readers
- Ensure touch targets are at least 44x44px

## Code Quality Standards

### Python (Backend)
- Follow PEP 8 style guide
- Use type hints where beneficial
- Keep functions under 50 lines when possible
- One responsibility per function
- Use descriptive variable names (no single letters except loop iterators)
- Add docstrings only for complex functions
- Handle exceptions appropriately, never use bare `except:`
- Use context managers for resource management
- Keep routes thin - move business logic to separate functions

### JavaScript (Frontend)
- Use const by default, let when reassignment needed, avoid var
- Use async/await instead of promise chains
- Use arrow functions for callbacks
- Prefer template literals over string concatenation (except when user data is involved)
- Use destructuring for cleaner code
- Keep functions small and focused
- Use meaningful variable names
- Avoid nested callbacks (callback hell)
- Handle errors in async functions with try/catch

### HTML/CSS
- Use semantic HTML5 elements
- Maintain consistent indentation (4 spaces)
- Keep inline styles minimal (use classes)
- Use CSS variables for theming
- BEM-like naming for CSS classes when needed
- Mobile-first media queries
- Avoid !important unless absolutely necessary

### Database
- Use ORM methods (SQLAlchemy)
- Create indexes for frequently queried fields
- Use timezone-aware datetime objects
- Implement proper foreign key constraints
- Add database migrations for schema changes
- Avoid N+1 query problems

### Error Handling
- Log errors server-side for debugging
- Return user-friendly error messages
- Use appropriate HTTP status codes
- Never expose stack traces to users
- Handle rate limit violations gracefully
- Provide actionable error messages

### Testing (When Implemented)
- Write tests for critical security functions
- Test authentication flows thoroughly
- Mock external dependencies
- Test edge cases and error conditions
- Maintain test coverage above 80%

### Performance
- Minimize database queries (use eager loading)
- Implement caching where appropriate
- Optimize images before upload
- Lazy load non-critical resources
- Debounce user input handlers
- Use CDN for static assets when possible

### Documentation
- Keep comments minimal - write self-documenting code
- Document complex algorithms or business logic
- Maintain API documentation for OAuth endpoints
- Update README for deployment changes
- Document environment variables needed

## Development Workflow

### Git Practices
- Write clear commit messages
- Keep commits atomic and focused
- Branch naming: feature/, bugfix/, security/
- Never commit secrets or credentials
- Review changes before committing

### Environment Setup
- Use virtual environments for Python dependencies
- Set environment variables via .env file (never committed)
- Required env vars: SECRET_KEY, DATABASE_URL
- Development uses SQLite, production uses PostgreSQL

### Deployment Considerations
- Never run with debug=True in production
- Use gunicorn as WSGI server
- Set up proper logging
- Configure firewall rules
- Use environment-specific configs
- Implement health check endpoints
- Set up automated backups

## Common Patterns

### Rendering User Data Safely
```javascript
const element = document.createElement('div');
element.textContent = userData;
parentElement.appendChild(element);
```

### Creating Links Safely
```javascript
const link = document.createElement('a');
const sanitized = sanitizeUrl(userUrl);
if (sanitized) {
    link.href = sanitized;
    link.textContent = 'Visit';
}
```

### API Error Handling
```python
try:
    # operation
    return jsonify({"message": "Success"}), 200
except SpecificException as e:
    return jsonify({"message": "User-friendly error"}), 400
except Exception:
    return jsonify({"message": "Internal server error"}), 500
```

### Token Verification Pattern
```python
token = request.headers.get("Authorization")
if not token:
    return jsonify({"message": "Token is missing"}), 401
try:
    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    user = User.query.get(data["user_id"])
    # proceed with request
except jwt.ExpiredSignatureError:
    return jsonify({"message": "Token has expired"}), 401
except jwt.InvalidTokenError:
    return jsonify({"message": "Invalid token"}), 401
```

## File Structure
```
/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── gunicorn_config.py    # Production server config
├── instance/             # SQLite database (gitignored)
├── static/
│   ├── security.js       # XSS prevention utilities
│   ├── *.html           # Frontend pages
│   └── uploads/         # User uploaded files
└── .github/
    └── COPILOT-INSTRUCTIONS.md
```

## When Adding New Features

1. **Security First**: Consider security implications before implementation
2. **Validate Input**: Add both client and server-side validation
3. **Sanitize Output**: Use XSS prevention utilities
4. **Error Handling**: Handle all error cases gracefully
5. **Consistent Styling**: Follow existing design patterns
6. **Mobile Responsive**: Test on mobile viewports
7. **Update Documentation**: Keep this file updated with new patterns

## Anti-Patterns to Avoid

❌ `innerHTML` with user data
❌ `eval()` or `Function()` constructor
❌ Inline event handlers with user data
❌ SQL string concatenation
❌ Hardcoded secrets
❌ Generic exception catching without logging
❌ Returning detailed errors to users
❌ Unvalidated redirects
❌ File operations without validation
❌ Missing CSRF protection on state changes
❌ Overly permissive CORS policies
❌ Missing rate limiting
❌ Weak password requirements
❌ Long-lived authentication tokens
❌ Exposing internal implementation details

## Resources

- Flask Security: https://flask.palletsprojects.com/en/2.3.x/security/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OAuth 2.0 RFC: https://datatracker.ietf.org/doc/html/rfc6749
- Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

## Questions?

When in doubt:
1. Prioritize security over convenience
2. Follow established patterns in the codebase
3. Validate and sanitize all user input
4. Use existing utility functions
5. Test with malicious input

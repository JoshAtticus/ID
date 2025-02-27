## Creating an OAuth App using SCEAID

### Creating an OAuth App
1. Go to the developer dashboard
2. Click "Create New App"
3. Fill in required details:
- Name: Your application name
- Redirect URI: Your redirect URI
- Website (optional): Your app's website for easy access from SCEAID Dashboard

After creating, you'll receive:
- Client ID
- Client Secret (save this, it won't be shown again)

### Test with Example Client
The repository includes a test client in oauth-example-client (this folder):

```bash
cd oauth-example-client/oauth-example-client
npm install
```

Update the .env file with your credentials:

```bash
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
```

Start the test client:

```bash
node server.js
```

### Testing OAuth Flow

- Visit `http://localhost:3000`
- Click "Login with SCEAID"
- Login to your SCEAID account if needed
- Review and approve the requested permissions
- You'll be redirected back with your profile info

### Available Scopes
The OAuth API supports these scopes:

- `name` - Access user's full name
- `email` - Access email address
- `profile_picture` - Access profile picture
- `student_number` - Access student number

Include the desired scopes in the authorization URL, seperated by commas:

```bash
/oauth/authorize?scope=name,email,profile_picture
```

### Security Notes
- Store client secret securely
- Use HTTPS in production
- Validate tokens and scopes
- Never commit credentials to source control
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = 3000;

console.log('Loaded CLIENT_ID:', process.env.CLIENT_ID ? 'Present' : 'Missing');
console.log('Loaded CLIENT_SECRET:', process.env.CLIENT_SECRET ? 'Present' : 'Missing');

// Store state temporarily (in production, use sessions or Redis)
const stateStore = new Map();

app.get('/', (req, res) => {
    res.send(`
        <h1>OAuth Example</h1>
        <a href="/login" style="
            display: inline-block;
            background: #1a73e8;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 4px;
            font-family: 'Google Sans', sans-serif;
        ">Login</a>
    `);
});

app.get('/login', (req, res) => {
    // Generate a secure random state parameter
    const state = crypto.randomBytes(16).toString('hex');
    
    // Store the state temporarily (expires in 10 minutes)
    stateStore.set(state, { timestamp: Date.now() });
    
    // Clean up old states
    for (const [key, value] of stateStore.entries()) {
        if (Date.now() - value.timestamp > 600000) { // 10 minutes
            stateStore.delete(key);
        }
    }
    
    // Request all available scopes with state parameter (scopes are space-separated)
    const authUrl = `http://localhost:5002/oauth/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=http://localhost:3000/callback&scope=name email profile_picture dob&state=${state}`;
    res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
    const { code, state } = req.query;
    
    // Verify state parameter
    if (!state || !stateStore.has(state)) {
        return res.send(`
            <div style="
                font-family: 'Google Sans', sans-serif;
                max-width: 600px;
                margin: 40px auto;
                padding: 20px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 1px 2px rgba(60, 64, 67, 0.3);
                color: #d93025;
            ">
                <h2>Security Error</h2>
                <p>Invalid state parameter. This could be a CSRF attack.</p>
                <a href="/" style="color: #1a73e8;">← Try Again</a>
            </div>
        `);
    }
    
    // Remove the state after validation
    stateStore.delete(state);
    
    try {
        const params = new URLSearchParams();
        params.append('grant_type', 'authorization_code');
        params.append('code', code);
        params.append('client_id', process.env.CLIENT_ID);
        params.append('client_secret', process.env.CLIENT_SECRET);
        params.append('redirect_uri', 'http://localhost:3000/callback');

        // Add debug information
        console.log('Authorization Code:', code);
        console.log('State:', state);
        console.log('Client ID:', process.env.CLIENT_ID);
        console.log('Client Secret:', process.env.CLIENT_SECRET);

        const tokenResponse = await axios.post('http://localhost:5002/oauth/token', 
            params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const accessToken = tokenResponse.data.access_token;
        console.log('Access Token:', accessToken);
        console.log('Token Response:', tokenResponse.data);

        const userResponse = await axios.get('http://localhost:5002/oauth/userinfo', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        const user = userResponse.data;

        // Display ALL information including OAuth details
        res.send(`
            <div style="
                font-family: 'Google Sans', sans-serif;
                max-width: 800px;
                margin: 40px auto;
                padding: 20px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 1px 2px rgba(60, 64, 67, 0.3);
            ">
                <h2>OAuth Information</h2>
                <div style="
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 10px 0;
                    font-family: monospace;
                ">
                    <p><strong>Client ID:</strong> ${process.env.CLIENT_ID}</p>
                    <p><strong>Client Secret:</strong> ${process.env.CLIENT_SECRET}</p>
                    <p><strong>State:</strong> ${state}</p>
                    <p><strong>Authorization Code:</strong> ${code}</p>
                    <p><strong>Access Token:</strong> ${accessToken}</p>
                    <p><strong>Token Type:</strong> ${tokenResponse.data.token_type}</p>
                    <p><strong>Scope:</strong> ${tokenResponse.data.scope}</p>
                </div>

                <h2>User Information</h2>
                ${user.profile_picture ? `
                    <img src="${user.profile_picture}" 
                         style="width: 150px; height: 150px; border-radius: 50%; margin: 20px 0; border: 3px solid #1a73e8;"
                    >
                ` : ''}
                <div style="margin: 20px 0;">
                    ${Object.entries(user).map(([key, value]) => `
                        <div style="
                            padding: 10px;
                            margin: 5px 0;
                            background: #f8f9fa;
                            border-radius: 4px;
                        ">
                            <strong>${key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ')}:</strong> 
                            ${typeof value === 'object' ? JSON.stringify(value, null, 2) : value}
                        </div>
                    `).join('')}
                </div>
                <hr>
                <div style="margin-top: 20px;">
                    <a href="/" style="
                        color: #1a73e8;
                        text-decoration: none;
                        font-weight: 500;
                    ">← Back to Home</a>
                </div>
            </div>
        `);
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
        res.send(`
            <div style="
                font-family: 'Google Sans', sans-serif;
                max-width: 600px;
                margin: 40px auto;
                padding: 20px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 1px 2px rgba(60, 64, 67, 0.3);
                color: #d93025;
            ">
                <h2>Authentication Error</h2>
                <pre style="
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                    overflow-x: auto;
                ">${JSON.stringify(error.response?.data || error.message, null, 2)}</pre>
                <a href="/" style="color: #1a73e8;">← Try Again</a>
            </div>
        `);
    }
});

app.listen(port, () => {
    console.log(`Example client running at http://localhost:${port}`);
});
const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const port = 3000;

console.log('Loaded CLIENT_ID:', process.env.CLIENT_ID ? 'Present' : 'Missing');
console.log('Loaded CLIENT_SECRET:', process.env.CLIENT_SECRET ? 'Present' : 'Missing');

app.get('/', (req, res) => {
    res.send(`
        <h1>SCEAID OAuth Example</h1>
        <a href="/login" style="
            display: inline-block;
            background: #1a73e8;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 4px;
            font-family: 'Google Sans', sans-serif;
        ">Login with SCEAID</a>
    `);
});

app.get('/login', (req, res) => {
    res.redirect(`http://localhost:5002/oauth/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=http://localhost:3000/callback&scope=name,email,profile_picture`);
});

app.get('/callback', async (req, res) => {
    const { code } = req.query;
    
    try {
        // Create form data
        const params = new URLSearchParams();
        params.append('code', code);
        params.append('client_id', process.env.CLIENT_ID);
        params.append('client_secret', process.env.CLIENT_SECRET);

        console.log('Sending token request with:', {
            code,
            client_id: process.env.CLIENT_ID?.substring(0, 4) + '...',
            client_secret: process.env.CLIENT_SECRET ? '***' : 'Missing'
        });

        // Exchange code for token
        const tokenResponse = await axios.post('http://localhost:5002/oauth/token', 
            params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const accessToken = tokenResponse.data.access_token;

        // Get user info
        const userResponse = await axios.get('http://localhost:5002/oauth/userinfo', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        const user = userResponse.data;

        // Display user info
        res.send(`
            <div style="
                font-family: 'Google Sans', sans-serif;
                max-width: 600px;
                margin: 40px auto;
                padding: 20px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 1px 2px rgba(60, 64, 67, 0.3);
            ">
                <h2>Welcome ${user.name}!</h2>
                ${user.profile_picture ? `
                    <img src="${user.profile_picture}" 
                         style="width: 100px; height: 100px; border-radius: 50%; margin: 20px 0;"
                    >
                ` : ''}
                <p><strong>Email:</strong> ${user.email}</p>
                <hr>
                <a href="/" style="color: #1a73e8;">← Back to Home</a>
            </div>
        `);
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
        res.status(500).send('Error during authentication');
    }
});

app.listen(port, () => {
    console.log(`Example client running at http://localhost:${port}`);
});
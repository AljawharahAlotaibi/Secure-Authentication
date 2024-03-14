import express from 'express';
import bodyParser from 'body-parser';
import { hash , compare } from 'bcrypt';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {signin,signup } from './db/db.mjs';
import querystring from 'querystring';
import google_secret from './google_secret.json' assert { type: "json" };
import github_secret from './github_secret.json' assert { type: "json" };
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import base64url from 'base64url';

const { urlencoded } = bodyParser;
const app = express();

const CLIENT_GOOGLE_ID = google_secret.client_id
const CLIENT_GOOGLE_SECRET = google_secret.client_secret
const REDIRECT_GOOGLE_URI = google_secret.redirect_uris;

const CLIENT_GITHUB_ID = github_secret.client_id
const CLIENT_GITHUB_SECRET = github_secret.client_secret
const REDIRECT_GITHUB_URI = github_secret.redirect_uris;


const __dirname = dirname(fileURLToPath(import.meta.url));


app.use(urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

// Registration endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await hash(password, 10);
    const user = { username, password: hashedPassword };

    signup(username, user);

    res.send('User registered successfully');
  } catch (error) {
    res.status(500).send('Error registering new user');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  
    const { username, password } = req.body;
    let user = signin(username);
    if (!user) {
      return res.status(400).send('Invalid credentials');
    }
    const match = await compare(password, user.password);
    if (match) {
      res.send('Login successful');
    } else {
      res.status(400).send('Invalid credentials');
    }
});



// getting the authorization code from google
app.get('/auth/google', (req, res) => {
  const authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  const params = {
      client_id: CLIENT_GOOGLE_ID,
      redirect_uri: REDIRECT_GOOGLE_URI,
      response_type: 'code',
      scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',  // Do we need the email?
      access_type: 'online'
  };
  res.redirect(`${authorizationUrl}?${querystring.stringify(params)}`);
});
// exchanging the authorization code and then using it to get the access token
// and then using the access token to get the user's email address
app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
      return res.status(400).send('Authorization code is missing');
  }
  try {
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: querystring.stringify({
              code,
              client_id: CLIENT_GOOGLE_ID ,
              client_secret: CLIENT_GOOGLE_SECRET ,
              redirect_uri: REDIRECT_GOOGLE_URI,
              grant_type: 'authorization_code'
          })
      });

      if (!tokenResponse.ok) {
          throw new Error('Failed to exchange authorization code for access token');
      }

      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) {
          throw new Error('Access token is missing in the response');
      }

      const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
          headers: { Authorization: `Bearer ${accessToken}` }
      });

      if (!userInfoResponse.ok) {
          throw new Error('Failed to fetch user info');
      }

      const userData = await userInfoResponse.json();
      // send Login successful
      res.send(`
          <h1>Login successful</h1>
          <p>Welcome ${userData.email}</p>
      `);
      
  } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
  }
});


// getting the authorization code from GITHUB
app.get('/auth/github', (req, res) => {
  const authorizationUrl = 'https://github.com/login/oauth/authorize';
  const params = {
      client_id: CLIENT_GITHUB_ID,
      redirect_uri: REDIRECT_GITHUB_URI,
      response_type: 'code',
      scope: 'user',
      access_type: 'online'
  };
  res.redirect(`${authorizationUrl}?${querystring.stringify(params)}`);
});
// exchanging the authorization code and then using it to get the access token
// and then using the access token to get the user's info
app.get('/auth/github/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
      return res.status(400).send('Authorization code is missing');
  }
  try {
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json' // this header to explicitly request JSON response
      },
      body: querystring.stringify({
        code,
        client_id: CLIENT_GITHUB_ID,
        client_secret: CLIENT_GITHUB_SECRET,
        redirect_uri: REDIRECT_GITHUB_URI,
        grant_type: 'authorization_code'
      })
    });
  
    if (!tokenResponse.ok) {
      throw new Error('Failed to exchange authorization code for access token');
    }
  
    const tokenData = await tokenResponse.json(); // Parse response as JSON
    const accessToken = tokenData.access_token;
  
    if (!accessToken) {
      throw new Error('Access token is missing in the response');
    }
  
    const userInfoResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
  
    if (!userInfoResponse.ok) {
      throw new Error('Failed to fetch user info');
    }
  
    const userData = await userInfoResponse.json();
    // send Login successful
    res.send(`
      <h1>Login successful</h1>
      <p>Welcome ${userData.login}</p>
    `);
  
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


// WEBAUTHN


// Store authenticators temporarily. This should be replaced with a more secure storage in production.
const authenticators = {};


// Middleware to parse JSON request bodies
app.use(bodyParser.json());
// Serve static files from the 'public' directory
app.use(express.static('public'));

// WebAuthn configuration
const rpID = 'localhost'; // Relying Party Identifier - should match your domain in production
const expectedOrigin = 'http://localhost:3000'; // Expected origin of the requests

// Endpoint to start the registration process
app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Check if user already exists
  const user = await signin(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }

  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: base64url(Buffer.from(username)),
    userName: username,
    timeout: 60000, // Timeout for the request in milliseconds
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };

  // Send registration options to the client
  return res.send(registrationOptions);
});

// Endpoint to finish the registration process
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;

  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;

  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices:[{
        credentialPublicKey: base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID: base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };

    // Remove the temporary authenticator
    authenticators[username] = undefined;

    try {
      // Store the user in the database
      await signup(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }

    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify registration' });
  }
});

// Endpoint to start the login process
app.post('/login/start', async (req, res) => {
  const { username } = req.body;
  // Verify if the user exists
  const user = await signin(username);
  if (!user) {
    return res.status(400).send({ error: 'User does not exist' });
  }

  // Generate authentication options
  const options = {
    rpID,
    timeout: 60000, // Timeout for the request in milliseconds
    userVerification: 'required',
    allowCredentials: user.devices.map((device) => ({
      id: new Uint8Array(base64url.toBuffer(device.credentialID)),
      type: 'public-key',
      transports: device.transports,
    })),
  };

  const authenticationOptions = await generateAuthenticationOptions(options);

  // Store the challenge for later use during verification
  authenticators[username] = {
    currentChallenge: authenticationOptions.challenge,
  };

  // Send authentication options to the client
  return res.send(authenticationOptions);
});

// Endpoint to finish the login process
app.post('/login/finish', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const expectedChallenge = authenticators[username].currentChallenge;

  const user = await signin(username);
  const device = user.devices[0];

  let verification;
  try {
    // Verify the authentication response
    verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: new Uint8Array(base64url.toBuffer(device.credentialID)),
        credentialPublicKey: new Uint8Array(base64url.toBuffer(device.credentialPublicKey)),
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Send the verification result to the client
  const { verified } = verification;
  if (verified) {
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify login' });
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});

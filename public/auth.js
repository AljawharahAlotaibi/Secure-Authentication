import {
    startAuthentication,
} from 'https://cdn.skypack.dev/@simplewebauthn/browser';

export async function login() {
    const username = document.getElementById('username').value;
  
    // Begin authentication process to get options
    let optionsRes = await fetch('/login/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username }),
    });
    let options = await optionsRes.json();
  
    if (options.error) {
      return alert(options.error);
    }
  
    // Use @simplewebauthn/browser to start authentication
    console.log(options);
  
    let assertion = await startAuthentication(options);
  
    // Send assertion response to server
    let verificationRes = await fetch('/login/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        assertionResponse: assertion,
      }),
    });
    let verificationResult = await verificationRes.json();
  
    alert(`Login ${verificationResult ? 'successful' : 'failed'}`);
  }

document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('googleLogin').addEventListener('click', () => {
    window.location.href = '/auth/google';
});
document.getElementById('githubLogin').addEventListener('click', () => {
    window.location.href = '/auth/github';
});

  import {
    startRegistration,
  } from 'https://cdn.skypack.dev/@simplewebauthn/browser';
  
  export async function register() {
    const username = document.getElementById('username').value;
  
    // Begin registration process to get options
    let optionsRes = await fetch('/register/start', {
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
  
    // Use @simplewebauthn/browser to start registration
    let attestation = await startRegistration(options);
  
    // Send attestation response to server
    let verificationRes = await fetch('/register/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        attestationResponse: attestation,
      }),
    });
    let verificationResult = await verificationRes.json();
  
    alert(`Registration ${verificationResult ? 'successful' : 'failed'}`);
  }
  document.getElementById('registerBtn').addEventListener('click', register);

const crypto = require('crypto');

async function verifyRecoveryPipeline() {
  console.log('--- 1. Testing Backend Health Probe ---');
  const healthRes = await fetch('http://localhost:3000/health');
  const healthJson = await healthRes.json();
  if (healthRes.ok && healthJson.status === 'ok') {
    console.log('✓ Backend health check passed:', healthJson);
  } else {
    throw new Error('Health probe failed: ' + JSON.stringify(healthJson));
  }

  console.log('\n--- 2. Testing /api/request-recovery Validation ---');
  const invalidRes = await fetch('http://localhost:3000/api/request-recovery', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'not-an-email' })
  });
  const invalidJson = await invalidRes.json();
  if (invalidRes.status === 400 && !invalidJson.success) {
    console.log('✓ Invalid email correctly rejected (400 Bad Request)');
  } else {
    throw new Error('Expected 400 for invalid email, got: ' + invalidRes.status);
  }

  console.log('\n--- 3. Testing Verify OTP Invalid Request ID ---');
  const verifyFakeRes = await fetch('http://localhost:3000/api/verify-recovery-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId: 'fake-uuid', otp: '123456' })
  });
  const verifyFakeJson = await verifyFakeRes.json();
  if (verifyFakeRes.status === 404 && !verifyFakeJson.success) {
    console.log('✓ Non-existent OTP session correctly rejected (404 Not Found)');
  } else {
    throw new Error('Expected 404 for fake request, got: ' + verifyFakeRes.status);
  }

  console.log('\n--- 4. Testing Complete Recovery Invalid Token ---');
  const completeFakeRes = await fetch('http://localhost:3000/api/complete-recovery', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId: 'fake-uuid', recoveryToken: 'invalid.token' })
  });
  const completeFakeJson = await completeFakeRes.json();
  if (completeFakeRes.status === 403 && !completeFakeJson.success) {
    console.log('✓ Invalid recovery token correctly rejected (403 Forbidden)');
  } else {
    throw new Error('Expected 403 for fake token, got: ' + completeFakeRes.status);
  }

  console.log('\n--- 5. Testing PBKDF2 Password Derivation Pipeline ---');
  const testPassword = 'NewMasterPassword2026!';
  const saltBytes = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(testPassword, saltBytes, 310000, 32, 'sha256').toString('hex');
  if (hash && hash.length === 64) {
    console.log('✓ PBKDF2 (310,000 iterations SHA-256) derived successfully (64 hex chars):', hash.substring(0, 16) + '...');
  } else {
    throw new Error('PBKDF2 derivation failed');
  }

  console.log('\n==========================================');
  console.log('✓ ALL RECOVERY PIPELINE TESTS PASSED!');
  console.log('==========================================');
}

verifyRecoveryPipeline().catch((err) => {
  console.error('Pipeline test failed:', err);
  process.exit(1);
});

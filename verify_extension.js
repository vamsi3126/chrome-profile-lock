const fs = require('fs');
const path = require('path');

const baseDir = path.resolve(__dirname, 'chrome-profile-lock');
const manifestPath = path.join(baseDir, 'manifest.json');

console.log('--- 1. MANIFEST JSON VALIDATION ---');
const raw = fs.readFileSync(manifestPath, 'utf8');
const manifest = JSON.parse(raw);
console.log('Manifest JSON is valid.');
console.log('Manifest version:', manifest.manifest_version);
console.log('Name:', manifest.name);
console.log('Permissions:', manifest.permissions);

console.log('\n--- 2. FILE EXISTENCE CHECK ---');
const filesToCheck = [
  manifest.background.service_worker,
  ...manifest.content_scripts[0].js,
  ...manifest.content_scripts[0].css,
  manifest.options_ui.page,
  manifest.icons['16'],
  manifest.icons['48'],
  manifest.icons['128'],
  manifest.action.default_icon['16'],
  manifest.action.default_icon['48'],
  manifest.action.default_icon['128'],
  'setup.html',
  'setup.js',
  'setup.css',
  'lock.html',
  'lock.js',
  'lock.css',
  'options.html',
  'options.js',
  'options.css'
];

let allExist = true;
for (const file of new Set(filesToCheck)) {
  const full = path.join(baseDir, file);
  if (!fs.existsSync(full)) {
    console.error('MISSING:', file);
    allExist = false;
  } else {
    console.log('EXISTS:', file);
  }
}

console.log('\n--- 3. EXTERNAL DEPENDENCY CHECK ---');
const htmlFiles = ['setup.html', 'lock.html', 'options.html'];
for (const h of htmlFiles) {
  const content = fs.readFileSync(path.join(baseDir, h), 'utf8');
  if (content.includes('http://') || content.includes('https://')) {
    const matches = content.match(/<script[^>]+src=["'](https?:[^"']+)["']/gi);
    if (matches) {
      console.error('External script found in', h, matches);
      allExist = false;
    }
  }
}
console.log('Zero external script/style dependencies detected.');

if (allExist) {
  console.log('\nVERIFICATION RESULT: ALL CHECKS PASSED SUCCESSFULLY!');
} else {
  console.error('\nVERIFICATION FAILED');
  process.exit(1);
}

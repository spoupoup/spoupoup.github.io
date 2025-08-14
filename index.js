/**
 * Calc + Hidden GitHub Share (Node/Express)
 * -----------------------------------------------------------
 * Single-file project:
 * - Serves a feature-rich calculator web app
 * - Holding the "2" key for 5 seconds opens a hidden /share page
 * - /share page supports signup/login and file sharing by 5-digit codes
 * - Files are uploaded to a GitHub repo via Contents API (if env is set),
 *   otherwise stored locally under ./shares as a fallback.
 *
 * ENV VARS (recommended):
 *   PORT=8080
 *   SESSION_SECRET=some_long_random_string
 *   GITHUB_TOKEN=ghp_... (with repo scope)
 *   GITHUB_REPO=owner/repo   (example: myuser/universal-share)
 *   GITHUB_BRANCH=main       (optional, defaults to main)
 *
 * Quick start:
 *   npm init -y && npm i express express-session multer sqlite3 bcrypt @octokit/rest uuid
 *   node server.js
 *   Visit http://localhost:8080
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { Octokit } = require('@octokit/rest');
const { v4: uuidv4 } = require('uuid');

// --- Config ---
const PORT = process.env.PORT || 8080;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || null;
const GITHUB_REPO = process.env.GITHUB_REPO || null; // format: owner/repo
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';
const LOCAL_SHARE_DIR = path.join(process.cwd(), 'shares');

// Ensure local share dir exists for fallback
if (!fs.existsSync(LOCAL_SHARE_DIR)) fs.mkdirSync(LOCAL_SHARE_DIR, { recursive: true });

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

// File upload middleware
const upload = multer({ dest: path.join(process.cwd(), 'tmp_uploads') });

// --- DB Setup (SQLite) ---
const dbPath = path.join(process.cwd(), 'data.sqlite');
const db = new sqlite3.Database(dbPath);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL
  )`);
});

// --- GitHub Client (optional) ---
let octokit = null;
let ghOwner = null;
let ghRepo = null;
if (GITHUB_TOKEN && GITHUB_REPO && GITHUB_REPO.includes('/')) {
  octokit = new Octokit({ auth: GITHUB_TOKEN });
  [ghOwner, ghRepo] = GITHUB_REPO.split('/');
}

// --- Helper functions ---
function generate5DigitCode() {
  return Math.floor(10000 + Math.random() * 90000).toString();
}

function ensureAuthed(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

async function uploadToGitHub(targetPath, absoluteFilePath, commitMessage) {
  if (!octokit || !ghOwner || !ghRepo) return null;

  const content = fs.readFileSync(absoluteFilePath);
  const base64Content = content.toString('base64');

  try {
    // Ensure directories by creating the file directly (GitHub auto-creates path)
    const resp = await octokit.repos.createOrUpdateFileContents({
      owner: ghOwner,
      repo: ghRepo,
      path: targetPath,
      message: commitMessage || `Add file ${path.basename(targetPath)}`,
      content: base64Content,
      branch: GITHUB_BRANCH,
    });
    return resp.data;
  } catch (err) {
    console.error('GitHub upload error:', err.message);
    throw err;
  }
}

function localStore(targetPath, absoluteFilePath) {
  const fullDest = path.join(LOCAL_SHARE_DIR, targetPath);
  fs.mkdirSync(path.dirname(fullDest), { recursive: true });
  fs.copyFileSync(absoluteFilePath, fullDest);
  return { path: fullDest };
}

// --- Pages ---
const calculatorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>All-in-One Calculator</title>
  <style>
    :root { --bg:#0f172a; --panel:#111827; --btn:#1f2937; --txt:#e5e7eb; --accent:#22d3ee; }
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--txt);font:16px/1.4 system-ui,Segoe UI,Roboto}
    .wrap{max-width:900px;margin:40px auto;padding:16px}
    .header{display:flex;align-items:center;gap:12px}
    .logo{font-weight:800;font-size:20px;letter-spacing:.5px}
    .panel{background:var(--panel);border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
    .display{font-size:32px;padding:12px 16px;background:#0b1220;border-radius:12px;margin-bottom:12px;word-break:break-all;min-height:56px}
    .keys{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
    button{padding:14px 10px;border:0;border-radius:12px;background:var(--btn);color:var(--txt);font-weight:600;cursor:pointer}
    button:active{transform:scale(.98)}
    .accent{background:linear-gradient(135deg,#06b6d4,#22d3ee);color:#001016}
    .wide{grid-column: span 2}
    .row{display:flex;gap:8px}
    .small{font-size:12px;opacity:.85}
    .section{margin-top:16px}
    .history{max-height:160px;overflow:auto;background:#0b1220;border-radius:12px;padding:8px}
    .muted{opacity:.65}
    .hint{font-size:12px;margin-top:6px;color:#a5f3fc}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="logo">CalcPro ✦</div>
      <div class="muted">Scientific · Memory · History</div>
    </div>

    <div class="panel">
      <div class="display" id="display">0</div>
      <div class="keys" id="keys"></div>
      <div class="hint">Hold the number <b>2</b> for 5 seconds to open advanced features.</div>

      <div class="section">
        <div class="row">
          <button id="mc">MC</button>
          <button id="mr">MR</button>
          <button id="mplus">M+</button>
          <button id="mminus">M-</button>
        </div>
      </div>

      <div class="section">
        <div class="small muted">History</div>
        <div class="history" id="history"></div>
      </div>
    </div>
  </div>

<script>
(function(){
  const display = document.getElementById('display');
  const keys = document.getElementById('keys');
  const historyEl = document.getElementById('history');
  let current = '0';
  let memory = 0;
  let lastOp = null;
  let holdTimer = null;
  let holding2 = false;

  const layout = [
    'AC','⌫','%','/','7','8','9','*','4','5','6','-','1','2','3','+','0','.','=','^','√','sin','cos','tan','ln','log','π','e','(' ,')'
  ];

  function refresh(){ display.textContent = current; }

  function pushHistory(entry){
    const div = document.createElement('div');
    div.textContent = entry; historyEl.prepend(div);
  }

  function compute(expr){
    // Safe-ish evaluator
    const safe = expr
      .replace(/π/g, Math.PI)
      .replace(/e(?![a-zA-Z])/g, Math.E)
      .replace(/√/g, 'Math.sqrt')
      .replace(/sin/g,'Math.sin')
      .replace(/cos/g,'Math.cos')
      .replace(/tan/g,'Math.tan')
      .replace(/ln/g,'Math.log')
      .replace(/log/g,'(x)=>Math.log10(x)')
      .replace(/\^/g, '**');
    try {
      // eslint-disable-next-line no-new-func
      const f = new Function('return (function(){ const log10=(x)=>Math.log10(x); return ' + safe + '; })()');
      return f();
    } catch(e){ return 'Error'; }
  }

  function press(k){
    if(k==='AC'){ current='0'; refresh(); return; }
    if(k==='⌫'){ current = current.length>1? current.slice(0,-1):'0'; refresh(); return; }
    if(k==='='){
      const res = compute(current);
      pushHistory(current + ' = ' + res);
      current = String(res); refresh(); return;
    }
    if(['+','-','*','/','^','%'].includes(k)){
      current += k; refresh(); return;
    }
    if(['√','sin','cos','tan','ln','log'].includes(k)){
      if(k==='log') current = `(${current}).toString() && log10(${current})`; else current = `${k}(${current})`;
      refresh(); return;
    }
    if(k==='π' || k==='e' || k==='(' || k===')' || k==='.') { current += k; refresh(); return; }
    // digits
    if(/^[0-9]$/.test(k)){
      if(current==='0') current=k; else current+=k; refresh(); return;
    }
  }

  layout.forEach(k=>{
    const b = document.createElement('button');
    b.textContent = k; if(k==='=') b.classList.add('accent');
    if(k==='0') b.classList.add('wide');
    b.addEventListener('click',()=>press(k));
    keys.appendChild(b);
  });

  // Memory buttons
  document.getElementById('mc').onclick = ()=>{ memory=0; };
  document.getElementById('mr').onclick = ()=>{ current = String(memory); refresh(); };
  document.getElementById('mplus').onclick = ()=>{ const v=Number(compute(current)); if(!isNaN(v)) memory+=v; };
  document.getElementById('mminus').onclick = ()=>{ const v=Number(compute(current)); if(!isNaN(v)) memory-=v; };

  // Keyboard support + hidden feature on holding "2"
  window.addEventListener('keydown',(e)=>{
    const k = e.key;
    if(k==='2' && !holding2){
      holding2 = true;
      holdTimer = setTimeout(()=>{ window.location.href='/share'; }, 5000);
    }
    if(k==='Enter') press('=');
    if(k==='Backspace') press('⌫');
    if('0123456789.+-*/%^()'.includes(k)) press(k);
  });
  window.addEventListener('keyup',(e)=>{
    if(e.key==='2'){
      holding2=false; if(holdTimer){ clearTimeout(holdTimer); holdTimer=null; }
    }
  });

  refresh();
})();
</script>
</body>
</html>`;

const shareHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Universal Share — GitHub-backed</title>
  <style>
    body{margin:0;background:#0b1220;color:#e5e7eb;font:16px system-ui,Segoe UI,Roboto}
    .wrap{max-width:900px;margin:40px auto;padding:16px}
    .card{background:#0f172a;border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
    input,button{padding:12px;border-radius:10px;border:0}
    input{width:100%;margin:6px 0;background:#0b1220;color:#e5e7eb}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    button{cursor:pointer;background:linear-gradient(135deg,#06b6d4,#22d3ee);color:#001016;font-weight:700}
    .muted{opacity:.7}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2>Universal Share</h2>
      <p class="muted">Backed by GitHub Contents API (or local fallback). Login or sign up to get your unique 5-digit code and share files to anyone by their code.</p>
      <div class="grid">
        <div>
          <h3>Login</h3>
          <input id="li_user" placeholder="Username" />
          <input id="li_pass" type="password" placeholder="Password" />
          <button id="login_btn">Login</button>
        </div>
        <div>
          <h3>Sign up</h3>
          <input id="su_user" placeholder="Username" />
          <input id="su_pass" type="password" placeholder="Password" />
          <button id="signup_btn">Create account</button>
        </div>
      </div>
      <hr style="margin:16px 0;border-color:#1e293b"/>
      <div id="authed" style="display:none">
        <p>Your code: <span id="mycode" class="mono"></span></p>
        <div class="row">
          <input id="target_code" maxlength="5" placeholder="Recipient 5-digit code"/>
          <input id="file_note" placeholder="Optional note (filename prefix)"/>
          <input id="file_input" type="file" />
          <button id="send_btn">Send File</button>
        </div>
        <p class="muted">Files will be committed to the configured GitHub repo under <code>shares/&lt;code&gt;/</code> (or saved locally if GitHub isn't configured).</p>
        <button id="logout_btn" style="margin-top:12px; background:#fca5a5;color:#061318">Log out</button>
      </div>
      <p><a href="/" style="color:#67e8f9">← Back to Calculator</a></p>
    </div>
  </div>

<script>
(function(){
  const loginBtn = document.getElementById('login_btn');
  const signupBtn = document.getElementById('signup_btn');
  const liUser = document.getElementById('li_user');
  const liPass = document.getElementById('li_pass');
  const suUser = document.getElementById('su_user');
  const suPass = document.getElementById('su_pass');
  const authed = document.getElementById('authed');
  const mycode = document.getElementById('mycode');
  const targetCode = document.getElementById('target_code');
  const fileInput = document.getElementById('file_input');
  const fileNote = document.getElementById('file_note');
  const sendBtn = document.getElementById('send_btn');
  const logoutBtn = document.getElementById('logout_btn');

  async function me(){
    const r = await fetch('/api/me');
    if(r.ok){
      const d = await r.json();
      authed.style.display='block';
      mycode.textContent = d.code;
    } else {
      authed.style.display='none';
    }
  }

  loginBtn.onclick = async ()=>{
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:liUser.value,password:liPass.value})});
    if(r.ok){ await me(); } else alert('Login failed');
  };
  signupBtn.onclick = async ()=>{
    const r = await fetch('/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:suUser.value,password:suPass.value})});
    if(r.ok){ alert('Account created. You can now log in.'); } else alert('Signup failed');
  };
  sendBtn.onclick = async ()=>{
    if(!fileInput.files[0]) return alert('Choose a file');
    if(!/^\d{5}$/.test(targetCode.value)) return alert('Enter a 5-digit code');
    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    fd.append('code', targetCode.value);
    fd.append('note', fileNote.value||'');
    const r = await fetch('/api/share',{method:'POST',body:fd});
    const d = await r.json();
    if(r.ok){ alert('Sent! Commit/Path: '+(d.commit || d.path)); } else { alert('Error: '+(d.error||'unknown')); }
  };
  logoutBtn.onclick = async ()=>{ await fetch('/api/logout',{method:'POST'}); authed.style.display='none'; };

  me();
})();
</script>
</body>
</html>`;

// Routes
app.get('/', (req,res)=>{ res.type('html').send(calculatorHTML); });
app.get('/share', (req,res)=>{ res.type('html').send(shareHTML); });

// Auth API
app.post('/api/signup', (req,res)=>{
  const { username, password } = req.body || {};
  if(!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const code = generate5DigitCode();
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users(username,password_hash,code) VALUES(?,?,?)', [username, hash, code], function(err){
    if(err){ return res.status(400).json({ error: 'Username taken or DB error' }); }
    res.json({ ok: true });
  });
});

app.post('/api/login', (req,res)=>{
  const { username, password } = req.body || {};
  if(!username || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT * FROM users WHERE username=?', [username], (err,row)=>{
    if(err || !row) return res.status(400).json({ error: 'Invalid credentials' });
    if(!bcrypt.compareSync(password, row.password_hash)) return res.status(400).json({ error: 'Invalid credentials' });
    req.session.user = { id: row.id, username: row.username, code: row.code };
    res.json({ ok:true });
  });
});

app.post('/api/logout', (req,res)=>{ req.session.destroy(()=>res.json({ok:true})); });
app.get('/api/me', (req,res)=>{
  if(!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ username: req.session.user.username, code: req.session.user.code });
});

// Share API
app.post('/api/share', ensureAuthed, upload.single('file'), async (req,res)=>{
  try{
    const recipientCode = (req.body.code||'').trim();
    const note = (req.body.note||'').trim().replace(/[^a-zA-Z0-9-_ ]/g,'').slice(0,40);
    if(!/^\d{5}$/.test(recipientCode)) return res.status(400).json({ error: 'Bad recipient code' });
    if(!req.file) return res.status(400).json({ error: 'Missing file' });

    // Validate code exists (optional but nice)
    const row = await new Promise((resolve)=>{
      db.get('SELECT id FROM users WHERE code=?', [recipientCode], (err,r)=> resolve(r||null));
    });
    if(!row) return res.status(404).json({ error: 'Recipient code not found' });

    const ext = path.extname(req.file.originalname);
    const safeBase = path.basename(req.file.originalname, ext).replace(/[^a-zA-Z0-9-_ ]/g,'').slice(0,50) || 'file';
    const stamp = new Date().toISOString().replace(/[:.]/g,'-');
    const namePart = note ? `${note}-${safeBase}` : safeBase;
    const fileName = `${namePart}-${stamp}${ext}`;

    const relPath = path.join('shares', recipientCode, fileName).replace(/\\/g,'/');

    if (octokit) {
      const gh = await uploadToGitHub(relPath, req.file.path, `Share to ${recipientCode} from ${req.session.user.username}`);
      return res.json({ ok:true, commit: gh && gh.commit && gh.commit.sha });
    } else {
      const local = localStore(relPath, req.file.path);
      return res.json({ ok:true, path: local.path });
    }
  } catch(err){
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    if(req.file){ try{ fs.unlinkSync(req.file.path); } catch(e){} }
  }
});

// Start server
app.listen(PORT, ()=>{
  console.log(`Server running on http://localhost:${PORT}`);
  if(!octokit) console.log('GitHub not configured — using local storage fallback at ./shares');
});

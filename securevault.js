// securevault.js
// Minimal encrypted file vault (no obfuscation). Node >=16.
// npm i express multer sqlite3 bcryptjs uuid
// Run: MASTER_KEY=32bytehex(64chars) ADMIN_PASS=yourpass node securevault.js

const express = require('express');
const multer  = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const MASTER_KEY = (process.env.MASTER_KEY||'').trim();
if (MASTER_KEY.length !== 64) {
  console.error('ERROR: Set MASTER_KEY env to 32-byte hex (64 hex chars).');
  process.exit(1);
}
const MASTER = Buffer.from(MASTER_KEY,'hex');
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5*1024*1024 } });

const DATADIR = path.join(__dirname,'vault_data'); if (!fs.existsSync(DATADIR)) fs.mkdirSync(DATADIR);
const DB = new sqlite3.Database(path.join(DATADIR,'meta.db'));
DB.serialize(()=>{
  DB.run(`CREATE TABLE IF NOT EXISTS files(
    id TEXT PRIMARY KEY, name TEXT, ext TEXT, created INTEGER, nonce BLOB, tag BLOB, path TEXT, edit_pw_hash TEXT
  )`);
  DB.run(`CREATE TABLE IF NOT EXISTS tokens(
    token TEXT PRIMARY KEY, file_id TEXT, expires INTEGER
  )`);
});

function encrypt(buf){
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER, nonce);
  const out = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { out, nonce, tag };
}
function decrypt(buf, nonce, tag){
  const dec = crypto.createDecipheriv('aes-256-gcm', MASTER, nonce);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(buf), dec.final()]);
}
function createToken(fileId, ttlSec=300){
  const token = crypto.randomBytes(18).toString('hex');
  const expires = Date.now() + ttlSec*1000;
  DB.run('INSERT INTO tokens(token,file_id,expires) VALUES(?,?,?)', [token,fileId,expires]);
  return { token, expires };
}
function verifyToken(token, cb){
  DB.get('SELECT file_id,expires FROM tokens WHERE token=?', [token], (err,row)=>{
    if(err||!row) return cb(null);
    if (Date.now() > row.expires) { DB.run('DELETE FROM tokens WHERE token=?', [token]); return cb(null); }
    cb(row.file_id);
  });
}

// Upload file (multipart 'file'), optional edit_pw and ttl (seconds)
app.post('/upload', upload.single('file'), async (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({err:'no file'});
    const allowed = ['.lua','.txt'];
    const ext = path.extname(req.file.originalname || '').toLowerCase();
    if(!allowed.includes(ext)) return res.status(400).json({err:'bad ext'});
    const id = uuidv4();
    const enc = encrypt(req.file.buffer);
    const storeName = id + '.bin';
    fs.writeFileSync(path.join(DATADIR,storeName), enc.out);
    const edit_pw = req.body.edit_pw || '';
    const edit_hash = edit_pw ? await bcrypt.hash(edit_pw,10) : null;
    DB.run('INSERT INTO files(id,name,ext,created,nonce,tag,path,edit_pw_hash) VALUES(?,?,?,?,?,?,?,?)',
      [id, req.file.originalname, ext, Date.now(), enc.nonce, enc.tag, storeName, edit_hash]);
    const ttl = Math.max(60, parseInt(req.body.ttl||300));
    const tok = createToken(id, ttl);
    res.json({id, link:`/file/${id}?token=${tok.token}`, expires: new Date(tok.expires).toISOString()});
  }catch(e){ console.error(e); res.status(500).json({err:'server'}); }
});

// Download: requires token query param
app.get('/file/:id', (req,res)=>{
  const token = req.query.token || '';
  if(!token) return res.status(403).json({err:'token required'});
  verifyToken(token, (fileId)=>{
    if(!fileId || fileId !== req.params.id) return res.status(403).json({err:'invalid token'});
    DB.get('SELECT * FROM files WHERE id=?', [fileId], (err,row)=>{
      if(err||!row) return res.status(404).json({err:'not found'});
      const encbuf = fs.readFileSync(path.join(DATADIR,row.path));
      try{
        const plain = decrypt(encbuf, row.nonce, row.tag);
        res.setHeader('Content-Disposition', `attachment; filename="${row.name}"`);
        res.setHeader('Content-Type','application/octet-stream');
        res.send(plain);
      }catch(e){ console.error(e); res.status(500).json({err:'decrypt failed'}); }
    });
  });
});

// Request edit token: provide id + edit_pw (or ADMIN_PASS). Returns edit_token.
app.post('/request-edit', async (req,res)=>{
  const { id, edit_pw } = req.body || {};
  if(!id) return res.status(400).json({err:'id required'});
  DB.get('SELECT edit_pw_hash FROM files WHERE id=?',[id], async (err,row)=>{
    if(err||!row) return res.status(404).json({err:'not found'});
    if (String(edit_pw) === ADMIN_PASS) {
      const t = createToken(id, 300); return res.json({edit_token:t.token, expires: new Date(t.expires).toISOString()});
    }
    if(!row.edit_pw_hash) return res.status(403).json({err:'no edit password set'});
    const ok = await bcrypt.compare(String(edit_pw||''), row.edit_pw_hash);
    if(!ok) return res.status(403).json({err:'bad password'});
    const t = createToken(id, 300);
    res.json({edit_token:t.token, expires: new Date(t.expires).toISOString()});
  });
});

// Edit: multipart file + token in body. Replaces stored contents.
app.post('/edit/:id', upload.single('file'), (req,res)=>{
  const token = req.body.token || req.query.token || '';
  if(!token) return res.status(403).json({err:'token required'});
  verifyToken(token, (fileId)=>{
    if(!fileId || fileId !== req.params.id) return res.status(403).json({err:'invalid token'});
    if(!req.file) return res.status(400).json({err:'no file'});
    DB.get('SELECT * FROM files WHERE id=?', [fileId], (err,row)=>{
      if(err||!row) return res.status(404).json({err:'not found'});
      const enc = encrypt(req.file.buffer);
      const storeName = row.id + '.bin';
      fs.writeFileSync(path.join(DATADIR,storeName), enc.out);
      DB.run('UPDATE files SET name=?,ext=?,nonce=?,tag=? WHERE id=?',
        [req.file.originalname, path.extname(req.file.originalname), enc.nonce, enc.tag, row.id]);
      res.json({ok:true});
    });
  });
});

// Delete: requires token in body
app.post('/delete/:id', express.json(), (req,res)=>{
  const token = req.body.token || '';
  if(!token) return res.status(403).json({err:'token required'});
  verifyToken(token, (fileId)=>{
    if(!fileId || fileId !== req.params.id) return res.status(403).json({err:'invalid token'});
    DB.get('SELECT path FROM files WHERE id=?', [fileId], (err,row)=>{
      if(row && row.path) {
        try{ fs.unlinkSync(path.join(DATADIR,row.path)); }catch(e){}
      }
      DB.run('DELETE FROM files WHERE id=?', [fileId]);
      DB.run('DELETE FROM tokens WHERE file_id=?', [fileId]);
      res.json({deleted:true});
    });
  });
});

// Simple health
app.get('/', (req,res)=> res.send('securevault up'));

app.listen(PORT, ()=> console.log(`securevault listening on ${PORT}`));

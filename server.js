// server.js
// SecureVault - Node + Express minimal secure paste (AES-GCM, per-file CEK, scrypt hashes)
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

const DATA = path.join(__dirname, 'vault_data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA);

const META = path.join(DATA, 'meta.json');
const meta = fs.existsSync(META) ? JSON.parse(fs.readFileSync(META)) : {};
function saveMeta(){ fs.writeFileSync(META, JSON.stringify(meta, null, 2)); }

const storage = multer.memoryStorage();
const upload = multer({ storage });

/* Crypto helpers */
const MASTER_KEY = (() => {
  const env = process.env.MASTER_KEY;
  if (env && env.length >= 32) return crypto.createHash('sha256').update(env).digest();
  // fallback: ephemeral key (not recommended on prod)
  console.warn('WARNING: Using ephemeral MASTER_KEY. Set MASTER_KEY env var to persist access between restarts.');
  return crypto.randomBytes(32);
})();

function randStr(len=9){ return crypto.randomBytes(len).toString('base64url'); }
function scryptHash(secret, salt=null){
  salt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(secret, salt, 64).toString('hex');
  return { salt, hash: derived };
}
function scryptVerify(secret, salt, hash){
  return crypto.scryptSync(secret, salt, 64).toString('hex') === hash;
}

/* Encrypt content with per-file key + AES-256-GCM */
function encryptContent(plaintext){
  const cek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext,'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();

  // encrypt cek with MASTER_KEY
  const iv2 = crypto.randomBytes(12);
  const c2 = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv2);
  const encCek = Buffer.concat([c2.update(cek), c2.final()]);
  const tag2 = c2.getAuthTag();

  return {
    ct: ct.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    encCek: encCek.toString('hex'),
    cekIv: iv2.toString('hex'),
    cekTag: tag2.toString('hex')
  };
}

function decryptContent(stored){
  const cekEnc = Buffer.from(stored.encCek, 'hex');
  const iv2 = Buffer.from(stored.cekIv, 'hex');
  const tag2 = Buffer.from(stored.cekTag, 'hex');
  const d2 = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv2);
  d2.setAuthTag(tag2);
  const cek = Buffer.concat([d2.update(cekEnc), d2.final()]);

  const ct = Buffer.from(stored.ct, 'hex');
  const iv = Buffer.from(stored.iv, 'hex');
  const tag = Buffer.from(stored.tag, 'hex');
  const d = crypto.createDecipheriv('aes-256-gcm', cek, iv);
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(ct), d.final()]);
  return plain.toString('utf8');
}

/* Create token like secureAb3 */
function makeToken(){
  let t;
  do { t = 'secure' + randStr(3); } while (meta[t]);
  return t;
}

/* Upload endpoint */
app.post('/upload', upload.single('file'), (req,res) => {
  try{
    let content = (req.body.text||'').trim();
    if (req.file && req.file.buffer && req.file.buffer.length) content = req.file.buffer.toString('utf8');
    if (!content) return res.status(400).json({error:'Nothing provided'});

    const require_key = !!req.body.require_key;
    const password = (req.body.password || '').trim();

    const token = makeToken();
    const enc = encryptContent(content);
    const fname = token + '.json';
    fs.writeFileSync(path.join(DATA, fname), JSON.stringify(enc));

    let access_key = null;
    if (require_key){
      access_key = randStr(10);
      const { salt, hash } = scryptHash(access_key);
      meta[token] = { file: fname, has_key:true, key_salt: salt, key_hash: hash, has_password: !!password };
    } else {
      meta[token] = { file: fname, has_key:false, has_password: !!password };
    }
    if (password){
      const { salt, hash } = scryptHash(password);
      meta[token].pass_salt = salt;
      meta[token].pass_hash = hash;
    }
    meta[token].created = Date.now();
    saveMeta();

    const link = `/v/${token}`;
    return res.json({ link, access_key });
  }catch(e){
    console.error(e);
    return res.status(500).json({error:'server error'});
  }
});

/* Web view: locked vault page or unlocked code display via POST */
app.get('/v/:token', (req,res) => {
  const t = req.params.token;
  if (!meta[t]) return res.status(404).send('Not found');
  // If Roblox client requests with ?key=..., return raw plaintext if key valid
  if (req.query.key){
    const info = meta[t];
    if (!info.has_key) return res.status(403).send('Key required for raw access');
    if (!scryptVerify(req.query.key, info.key_salt, info.key_hash)) return res.status(403).send('Invalid key');
    const stored = JSON.parse(fs.readFileSync(path.join(DATA, info.file),'utf8'));
    const plain = decryptContent(stored);
    res.set('Content-Type','text/plain; charset=utf-8');
    return res.send(plain);
  }
  // otherwise serve locked UI (frontend will POST to /v/:token/unlock to view)
  res.sendFile(path.join(__dirname,'public','viewer.html'));
});

app.post('/v/:token/unlock', express.urlencoded({extended:true}), (req,res) => {
  const t = req.params.token;
  if (!meta[t]) return res.status(404).json({ error: 'Not found' });
  const info = meta[t];
  const pw = (req.body.password||'').trim();
  if (!info.has_password) return res.status(403).json({ error: 'No password set for this vault' });
  if (!scryptVerify(pw, info.pass_salt, info.pass_hash)) return res.status(403).json({ error: 'Invalid password' });
  const stored = JSON.parse(fs.readFileSync(path.join(DATA, info.file),'utf8'));
  const plain = decryptContent(stored);
  res.json({ code: plain });
});

/* minimal status */
app.get('/health', (req,res)=> res.json({ok:true}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('SecureVault listening on', PORT));

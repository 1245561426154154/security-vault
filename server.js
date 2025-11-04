const express = require("express");
const multer = require("multer");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

const DATA_DIR = path.join(__dirname,"vault_data");
if(!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

let metaFile = path.join(DATA_DIR,"meta.json");
let meta = fs.existsSync(metaFile) ? JSON.parse(fs.readFileSync(metaFile)) : {};

function saveMeta(){ fs.writeFileSync(metaFile,JSON.stringify(meta)); }
function randomToken(len=8){ return crypto.randomBytes(len).toString("base64url"); }
function sha(s){ return crypto.createHash("sha256").update(s).digest("hex"); }
function encrypt(text){ return crypto.createCipheriv("aes-256-gcm", Buffer.from(process.env.KEY||crypto.randomBytes(32)), Buffer.alloc(16,0)).update(text,"utf8","hex"); }

app.post("/upload", upload.single("file"), (req,res)=>{
    let content = req.body.text || "";
    if(req.file) content = req.file.buffer.toString("utf8");
    if(!content) return res.send("Nothing uploaded");

    let password = req.body.password || "";
    let require_key = req.body.require_key ? true : false;
    let token = randomToken(6);
    let enc = encrypt(content);

    fs.writeFileSync(path.join(DATA_DIR,token+".enc"), enc);
    let access_key = require_key ? randomToken(12) : null;

    meta[token] = {file: token+".enc", has_password: !!password, pass_hash: password?sha(password):null, has_key: !!require_key, key_hash: access_key?sha(access_key):null};
    saveMeta();

    res.json({link:`/v/${token}`, access_key});
});

app.get("/v/:token", (req,res)=>{
    let t = req.params.token;
    if(!meta[t]) return res.status(404).send("Not found");
    let info = meta[t];
    let enc_file = path.join(DATA_DIR,info.file);
    if(!fs.existsSync(enc_file)) return res.status(404).send("File missing");

    if(req.query.key){
        if(!info.has_key || sha(req.query.key)!=info.key_hash) return res.status(403).send("Invalid key");
        return res.send(fs.readFileSync(enc_file,"utf8"));
    }

    res.sendFile(path.join(__dirname,"public","index.html"));
});

app.listen(process.env.PORT||3000,()=>console.log("SecureVault running"));

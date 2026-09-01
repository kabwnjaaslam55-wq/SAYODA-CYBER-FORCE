require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const NODE_ENV = process.env.NODE_ENV || "development";

if (!DATABASE_URL || !FRONTEND_ORIGIN) {
  console.error("DATABASE_URL and FRONTEND_ORIGIN are required.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10
});

app.use(helmet());
app.use(express.json({limit:"20kb"}));
app.use(cookieParser());

app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
  res.setHeader("Access-Control-Allow-Credentials","true");
  res.setHeader("Access-Control-Allow-Headers","Content-Type");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,OPTIONS");
  if(req.method==="OPTIONS") return res.sendStatus(204);
  next();
});

const loginLimiter = rateLimit({
  windowMs:15*60*1000, limit:10, standardHeaders:true, legacyHeaders:false,
  message:{error:"محاولات تسجيل دخول كثيرة. حاول لاحقًا."}
});
const registerLimiter = rateLimit({
  windowMs:60*60*1000, limit:5, standardHeaders:true, legacyHeaders:false,
  message:{error:"محاولات إنشاء حساب كثيرة. حاول لاحقًا."}
});

function normalizeUsername(v){ return String(v||"").trim().toLowerCase(); }
function validUsername(v){ return /^[a-zA-Z0-9_.-]{3,50}$/.test(v); }
function validPassword(v){ return typeof v==="string" && v.length>=8 && v.length<=128; }
function hash(v){ return crypto.createHash("sha256").update(v).digest("hex"); }
function cookieOpts(){
  return {httpOnly:true,secure:NODE_ENV==="production",sameSite:NODE_ENV==="production"?"none":"lax",
          maxAge:7*24*60*60*1000,path:"/"};
}
function safeVideoId(v){
  const x=String(v||"").trim();
  if(/^[a-zA-Z0-9_-]{11}$/.test(x)) return x;
  const m=x.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|v\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  return m?m[1]:null;
}

const videoData = require("./videos.json");
const videos=(Array.isArray(videoData.videos)?videoData.videos:[]).map(v=>({
  id:Number(v.id),title:String(v.title||""),description:String(v.description||""),
  youtube_id:safeVideoId(v.youtube_id),category:String(v.category||"Cybersecurity"),
  thumbnail:String(v.thumbnail||"sayed.png")
})).filter(v=>v.youtube_id);

async function auth(req,res,next){
  try{
    const raw=req.cookies.sayoda_session;
    if(!raw) return res.status(401).json({error:"غير مصرح."});
    const q=await pool.query(
      `SELECT s.id session_id,u.id user_id,u.username,u.active,u.is_admin
       FROM sessions s JOIN users u ON u.id=s.user_id
       WHERE s.token_hash=$1 AND s.expires_at>NOW()
       AND s.revoked_at IS NULL AND u.active=TRUE`,[hash(raw)]);
    if(!q.rowCount){
      res.clearCookie("sayoda_session",cookieOpts());
      return res.status(401).json({error:"الجلسة غير صالحة."});
    }
    req.auth=q.rows[0];
    await pool.query("UPDATE sessions SET last_seen=NOW() WHERE id=$1",[req.auth.session_id]);
    next();
  }catch(e){console.error(e);res.status(500).json({error:"خطأ داخلي."});}
}

function admin(req,res,next){
  if(!req.auth?.is_admin) return res.status(403).json({error:"هذه الصفحة للمشرف فقط."});
  next();
}

app.get("/health",async(_req,res)=>{
  try{await pool.query("SELECT 1");res.json({ok:true});}
  catch{res.status(503).json({ok:false});}
});

app.post("/api/register",registerLimiter,async(req,res)=>{
  try{
    const username=normalizeUsername(req.body.username),password=req.body.password;
    if(!validUsername(username)||!validPassword(password))
      return res.status(400).json({error:"اسم المستخدم أو كلمة المرور غير صالحين."});

    const exists=await pool.query("SELECT 1 FROM users WHERE username=$1",[username]);
    if(exists.rowCount) return res.status(409).json({error:"اسم المستخدم مستخدم بالفعل."});

    const passwordHash=await bcrypt.hash(password,12);
    const u=await pool.query(
      "INSERT INTO users(username,password_hash) VALUES($1,$2) RETURNING id,username,is_admin",
      [username,passwordHash]
    );

    res.status(201).json({ok:true,user:{username:u.rows[0].username,is_admin:u.rows[0].is_admin}});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر إنشاء الحساب."});}
});

app.post("/api/login",loginLimiter,async(req,res)=>{
  try{
    const username=normalizeUsername(req.body.username),password=req.body.password;
    if(!validUsername(username)||!validPassword(password))
      return res.status(400).json({error:"بيانات الدخول غير صحيحة."});

    const q=await pool.query(
      "SELECT id,username,password_hash,active,is_admin FROM users WHERE username=$1 LIMIT 1",[username]);
    const u=q.rows[0];
    if(!u||!u.active||!(await bcrypt.compare(password,u.password_hash)))
      return res.status(401).json({error:"اسم المستخدم أو كلمة المرور غير صحيحة."});

    await pool.query("UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL",[u.id]);
    const raw=crypto.randomBytes(32).toString("hex");
    await pool.query(
      `INSERT INTO sessions(id,user_id,token_hash,expires_at)
       VALUES($1,$2,$3,NOW()+INTERVAL '7 days')`,
      [uuidv4(),u.id,hash(raw)]
    );
    res.cookie("sayoda_session",raw,cookieOpts());
    res.json({ok:true,user:{username:u.username,is_admin:u.is_admin}});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تسجيل الدخول."});}
});

app.post("/api/logout",async(req,res)=>{
  try{
    const raw=req.cookies.sayoda_session;
    if(raw) await pool.query("UPDATE sessions SET revoked_at=NOW() WHERE token_hash=$1",[hash(raw)]);
    res.clearCookie("sayoda_session",cookieOpts());
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"تعذر تسجيل الخروج."});}
});

app.get("/api/me",auth,(req,res)=>{
  res.json({authenticated:true,user:{
    username:req.auth.username,is_admin:req.auth.is_admin
  }});
});

app.get("/api/videos",auth,async(req,res)=>{
  try{
    const q=await pool.query("SELECT video_id FROM video_access WHERE user_id=$1",[req.auth.user_id]);
    const allowed=new Set(q.rows.map(x=>String(x.video_id)));
    res.json({videos:videos.map(v=>({...v,unlocked:req.auth.is_admin||allowed.has(String(v.id))}))});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تحميل الفيديوهات."});}
});

app.put("/api/progress",auth,async(req,res)=>{
  try{
    const videoId=Number(req.body.video_id),progress=Number(req.body.progress);
    if(!Number.isInteger(videoId)||!Number.isFinite(progress)||progress<0||progress>100)
      return res.status(400).json({error:"بيانات التقدم غير صحيحة."});

    const access=await pool.query(
      "SELECT 1 FROM video_access WHERE user_id=$1 AND video_id=$2",[req.auth.user_id,videoId]);
    if(!access.rowCount && !req.auth.is_admin)
      return res.status(403).json({error:"ليس لديك صلاحية لهذا الفيديو."});

    await pool.query(
      `INSERT INTO video_progress(user_id,video_id,progress,updated_at)
       VALUES($1,$2,$3,NOW())
       ON CONFLICT(user_id,video_id)
       DO UPDATE SET progress=GREATEST(video_progress.progress,EXCLUDED.progress),updated_at=NOW()`,
      [req.auth.user_id,videoId,progress]);
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر حفظ التقدم."});}
});

/* ADMIN */
app.get("/api/admin/users",auth,admin,async(req,res)=>{
  try{
    const users=await pool.query(
      `SELECT u.id,u.username,u.active,
              COALESCE(array_agg(va.video_id) FILTER (WHERE va.video_id IS NOT NULL),'{}') video_ids
       FROM users u LEFT JOIN video_access va ON va.user_id=u.id
       WHERE u.is_admin=FALSE
       GROUP BY u.id ORDER BY u.id DESC`);
    res.json({users:users.rows,videos});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تحميل المستخدمين."});}
});

app.post("/api/admin/access",auth,admin,async(req,res)=>{
  try{
    const userId=Number(req.body.user_id),videoId=Number(req.body.video_id),grant=Boolean(req.body.grant);
    if(!Number.isInteger(userId)||!Number.isInteger(videoId))
      return res.status(400).json({error:"بيانات الصلاحية غير صحيحة."});

    const target=await pool.query("SELECT id,is_admin FROM users WHERE id=$1",[userId]);
    if(!target.rowCount||target.rows[0].is_admin)
      return res.status(400).json({error:"لا يمكن تعديل صلاحية المشرف."});

    if(!videos.some(v=>v.id===videoId))
      return res.status(404).json({error:"الفيديو غير موجود."});

    if(grant){
      await pool.query(
        `INSERT INTO video_access(user_id,video_id,granted_by)
         VALUES($1,$2,$3) ON CONFLICT(user_id,video_id) DO UPDATE SET granted_by=EXCLUDED.granted_by,granted_at=NOW()`,
        [userId,videoId,req.auth.user_id]);
    }else{
      await pool.query("DELETE FROM video_access WHERE user_id=$1 AND video_id=$2",[userId,videoId]);
    }
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تغيير الصلاحية."});}
});

app.post("/api/admin/users/:id/disable",auth,admin,async(req,res)=>{
  try{
    const id=Number(req.params.id);
    await pool.query("UPDATE users SET active=FALSE WHERE id=$1 AND is_admin=FALSE",[id]);
    await pool.query("UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1",[id]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"تعذر إيقاف الحساب."});}
});

app.listen(PORT,()=>console.log(`SAYODA backend listening on ${PORT}`));

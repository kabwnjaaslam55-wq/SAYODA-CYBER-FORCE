require("dotenv").config();
const {Pool}=require("pg");
const bcrypt=require("bcryptjs");
(async()=>{
 const username=String(process.argv[2]||"").trim().toLowerCase();
 const password=process.argv[3];
 if(!/^[a-zA-Z0-9_.-]{3,50}$/.test(username)||!password||password.length<8){
   console.error("Usage: node create-admin.js <username> <password>");
   process.exit(1);
 }
 const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:false});
 try{
   const hash=await bcrypt.hash(password,12);
   await pool.query(`INSERT INTO users(username,password_hash,is_admin)
     VALUES($1,$2,TRUE)
     ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash,is_admin=TRUE,active=TRUE`,
     [username,hash]);
   console.log("Admin ready:",username);
 }finally{await pool.end();}
})();

// server.js
// Backend สำหรับเชื่อมต่อบัญชี TikTok จริงด้วย TikTok Login Kit (OAuth v2)
// วิธีใช้งาน:
//   1) npm install
//   2) คัดลอก .env.example เป็น .env แล้วใส่ค่า TIKTOK_CLIENT_KEY / TIKTOK_CLIENT_SECRET /
//      TIKTOK_REDIRECT_URI ให้ตรงกับที่ลงทะเบียนไว้ใน TikTok Developer App
//   3) npm start แล้วเปิด http://localhost:3000 (หรือ APP_BASE_URL ที่ตั้งไว้)
//
// Endpoint ที่เปิดให้หน้าเว็บเรียก:
//   GET  /api/auth/tiktok/start      -> พาไปหน้า login ของ TikTok จริง
//   GET  /api/auth/tiktok/callback   -> TikTok เรียกกลับมาที่นี่หลังผู้ใช้อนุญาต
//   GET  /api/auth/tiktok/status     -> คืนสถานะว่าบัญชีนี้เชื่อมต่ออยู่หรือไม่ + ข้อมูลโปรไฟล์
//   POST /api/auth/tiktok/disconnect -> ยกเลิกการเชื่อมต่อ (revoke token + ล้าง session)

require("dotenv").config();

const crypto = require("crypto");
const path = require("path");
const express = require("express");
const session = require("express-session");

const {
  TIKTOK_CLIENT_KEY,
  TIKTOK_CLIENT_SECRET,
  TIKTOK_REDIRECT_URI,
  TIKTOK_SCOPES = "user.info.basic",
  SESSION_SECRET,
  PORT = 3000,
  APP_BASE_URL = `http://localhost:${PORT}`
} = process.env;

const TIKTOK_AUTHORIZE_URL = "https://www.tiktok.com/v2/auth/authorize/";
const TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/";
const TIKTOK_REVOKE_URL = "https://open.tiktokapis.com/v2/oauth/revoke/";
const TIKTOK_USER_INFO_URL = "https://open.tiktokapis.com/v2/user/info/";

if (!TIKTOK_CLIENT_KEY || !TIKTOK_CLIENT_SECRET || !TIKTOK_REDIRECT_URI) {
  console.warn(
    "[คำเตือน] ยังไม่ได้ตั้งค่า TIKTOK_CLIENT_KEY / TIKTOK_CLIENT_SECRET / TIKTOK_REDIRECT_URI ใน .env " +
      "— การเชื่อมต่อ TikTok จริงจะยังใช้งานไม่ได้จนกว่าจะตั้งค่าให้ครบ"
  );
}

const app = express();
app.use(express.json());
app.use(
  session({
    name: "creator_studio_sid",
    secret: SESSION_SECRET || "insecure-dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      // ตั้งเป็น true เมื่อรันบน HTTPS จริง
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

// เสิร์ฟหน้าเว็บ static (inedx.html และไฟล์อื่นในโฟลเดอร์เดียวกัน)
app.use(express.static(__dirname));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "inedx.html")));

// 1) เริ่ม OAuth: สร้าง state กันปลอมแปลง แล้วพาไปหน้า login ของ TikTok จริง
app.get("/api/auth/tiktok/start", (req, res) => {
  if (!TIKTOK_CLIENT_KEY || !TIKTOK_REDIRECT_URI) {
    return res.status(500).send("ยังไม่ได้ตั้งค่า TikTok Developer App ฝั่ง backend (.env)");
  }

  const state = crypto.randomBytes(16).toString("hex");
  req.session.tiktokOAuthState = state;

  const params = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    scope: TIKTOK_SCOPES,
    response_type: "code",
    redirect_uri: TIKTOK_REDIRECT_URI,
    state
  });

  res.redirect(`${TIKTOK_AUTHORIZE_URL}?${params.toString()}`);
});

// 2) TikTok เรียกกลับมาที่นี่พร้อม ?code=...&state=...
app.get("/api/auth/tiktok/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    return redirectToAccountPage(res, "error", errorDescription || error);
  }

  if (!state || state !== req.session.tiktokOAuthState) {
    return redirectToAccountPage(res, "error", "state ไม่ถูกต้อง กรุณาลองเชื่อมต่อใหม่อีกครั้ง");
  }
  delete req.session.tiktokOAuthState;

  if (!code) {
    return redirectToAccountPage(res, "error", "ไม่ได้รับ authorization code จาก TikTok");
  }

  try {
    const tokenResponse = await fetch(TIKTOK_TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache"
      },
      body: new URLSearchParams({
        client_key: TIKTOK_CLIENT_KEY,
        client_secret: TIKTOK_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: TIKTOK_REDIRECT_URI
      })
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || tokenData.error) {
      console.error("TikTok token exchange failed:", tokenData);
      return redirectToAccountPage(res, "error", "แลก access token กับ TikTok ไม่สำเร็จ");
    }

    const userInfoResponse = await fetch(
      `${TIKTOK_USER_INFO_URL}?fields=open_id,union_id,avatar_url,display_name`,
      { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
    );
    const userInfoData = await userInfoResponse.json();
    const profile = userInfoData?.data?.user || null;

    // เก็บ token/โปรไฟล์ไว้ใน session ฝั่ง server เท่านั้น (ไม่ส่ง client_secret/token ออกไปฝั่งหน้าเว็บ)
    req.session.tiktok = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: Date.now() + tokenData.expires_in * 1000,
      openId: tokenData.open_id,
      profile
    };

    return redirectToAccountPage(res, "connected");
  } catch (err) {
    console.error("TikTok OAuth callback error:", err);
    return redirectToAccountPage(res, "error", "เกิดข้อผิดพลาดระหว่างเชื่อมต่อ TikTok");
  }
});

// 3) สถานะการเชื่อมต่อปัจจุบัน ให้หน้าเว็บเรียกเช็คได้
app.get("/api/auth/tiktok/status", (req, res) => {
  const tiktok = req.session.tiktok;
  if (!tiktok) return res.json({ connected: false });

  res.json({
    connected: true,
    user: {
      displayName: tiktok.profile?.display_name || "บัญชี TikTok",
      avatarUrl: tiktok.profile?.avatar_url || null,
      openId: tiktok.openId
    }
  });
});

// 4) ตัดการเชื่อมต่อ: เพิกถอน token กับ TikTok แล้วล้าง session
app.post("/api/auth/tiktok/disconnect", async (req, res) => {
  const tiktok = req.session.tiktok;
  if (tiktok?.accessToken) {
    try {
      await fetch(TIKTOK_REVOKE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_key: TIKTOK_CLIENT_KEY,
          client_secret: TIKTOK_CLIENT_SECRET,
          token: tiktok.accessToken
        })
      });
    } catch (err) {
      console.warn("TikTok revoke token failed (เพิกเฉยต่อได้):", err.message);
    }
  }

  delete req.session.tiktok;
  res.json({ connected: false });
});

function redirectToAccountPage(res, status, message) {
  const params = new URLSearchParams({ tiktok: status });
  if (message) params.set("message", message);
  // query string ต้องอยู่ก่อนเครื่องหมาย # เสมอ เพื่อให้ location.search อ่านค่าได้
  res.redirect(`${APP_BASE_URL}/?${params.toString()}#account`);
}

app.listen(PORT, () => {
  console.log(`Creator Studio backend พร้อมใช้งานที่ ${APP_BASE_URL}`);
});

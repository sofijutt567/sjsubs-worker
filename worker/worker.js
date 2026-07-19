// ============================================
// 🚀 SJsubs — Cloudflare Worker (ALL-IN-ONE, v2)
// ============================================
// Domain: sjsubs.online (Worker Route on /category/*, /product/*, /all-products, /payment.html)
// Homepage (index.html) lives on Cloudflare Pages, same domain.
//
// Routes:
//   POST / (with X-Admin-Key) → R2 Image Upload
//   GET  /category/:name       → Category products page (KV cached)
//   GET  /product/:slug        → Product detail page (KV cached + SEO)
//   GET  /all-products         → All products page (KV cached)
//   GET  /payment.html         → WhatsApp checkout / order confirmation page
//   GET  /*                    → 404 Professional page
// ============================================

// ========== HELPERS ==========
function money(n) {
  return "₨" + Number(n || 0).toLocaleString();
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function starsHTML(rating, reviews) {
  const r = Math.max(0, Math.min(5, Number(rating) || 5));
  let html = '';
  for (let i = 1; i <= 5; i++) {
    if (r >= i) html += '<i class="fa-solid fa-star"></i>';
    else if (r >= i - 0.5) html += '<i class="fa-solid fa-star-half-stroke"></i>';
    else html += '<i class="fa-regular fa-star"></i>';
  }
  if (reviews) html += `<span class="count">(${reviews})</span>`;
  return html;
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

// ========== AUTH HELPERS (login / signup) ==========
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}

// Hashes a password with PBKDF2 (SHA-256, 100k iterations). If saltHex is not
// passed, a new random salt is generated (used on signup). Pass the stored
// saltHex back in on login to verify against the stored hash.
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

async function hmacSign(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return bytesToHex(new Uint8Array(sigBuf));
}

function sessionSecret(env) {
  // ⚠️ Set SESSION_SECRET in the Cloudflare dashboard (Worker → Settings → Variables)
  // for production. Falls back to a default so login still works if you forget.
  return (env && env.SESSION_SECRET) || "sjsubs-default-session-secret-change-me";
}

// Session token = base64(JSON payload) + "." + HMAC signature.
// Payload carries uid/name/email directly so we don't need a Firestore read
// on every page load just to check "is this visitor logged in".
async function createSessionToken(env, user) {
  const payload = JSON.stringify({
    uid: user.id, name: user.name, email: user.email,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
  });
  const payloadB64 = btoa(unescape(encodeURIComponent(payload)));
  const sig = await hmacSign(sessionSecret(env), payloadB64);
  return payloadB64 + "." + sig;
}

async function verifySessionToken(env, token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expectedSig = await hmacSign(sessionSecret(env), payloadB64);
  if (expectedSig !== sig) return null;
  try {
    const payload = JSON.parse(decodeURIComponent(escape(atob(payloadB64))));
    if (!payload.uid || !payload.exp || payload.exp < Date.now()) return null;
    return payload; // { uid, name, email, exp }
  } catch (e) { return null; }
}

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  header.split(";").forEach(function (pair) {
    const idx = pair.indexOf("=");
    if (idx > -1) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  });
  return out;
}

function sessionCookieHeader(token) {
  // 30 days, HttpOnly + Secure so it can't be read/stolen via JS, SameSite=Lax.
  return `sjsubs_session=${encodeURIComponent(token)}; Path=/; Max-Age=${30 * 24 * 60 * 60}; HttpOnly; Secure; SameSite=Lax`;
}

async function getLoggedInUser(request, env) {
  const cookies = parseCookies(request);
  const token = cookies["sjsubs_session"];
  if (!token) return null;
  return await verifySessionToken(env, token); // null if missing/invalid/expired
}

async function getUserByEmail(env, email) {
  const results = await queryFirestore(env, {
    from: [{ collectionId: "users" }],
    where: { fieldFilter: { field: { fieldPath: "email" }, op: "EQUAL", value: { stringValue: email.toLowerCase() } } },
    limit: 1
  });
  return results.length > 0 ? results[0] : null;
}

// ========== CONSTANTS ==========
const KV_CACHE_TTL = 86400;      // 24 hours for pages with data
const EMPTY_CACHE_TTL = 3600;    // 1 hour for empty categories
const LOGO_URL = "/images/logo.png";
const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB
const DEFAULT_SITE_URL = "https://sjsubs.online";
const DEFAULT_WHATSAPP = "923000000000"; // ⚠️ REPLACE with your real WhatsApp number (country code, no +, no spaces) — or set env.WHATSAPP_NUMBER in Cloudflare dashboard
const DEFAULT_WHATSAPP_ADMIN1 = "923447814644"; // Admin 1 — or override with env.WHATSAPP_ADMIN1 in Cloudflare dashboard
const DEFAULT_WHATSAPP_ADMIN2 = "923093623834"; // Admin 2 — or override with env.WHATSAPP_ADMIN2 in Cloudflare dashboard

// EmailJS (order notification emails) — or override any of these with the matching
// env var in Cloudflare dashboard (EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_PUBLIC_KEY, EMAILJS_PRIVATE_KEY, NOTIFY_EMAIL)
const DEFAULT_EMAILJS_SERVICE_ID = "service_cnflm3l";
const DEFAULT_EMAILJS_TEMPLATE_ID = "template_zqxls3k";
const DEFAULT_EMAILJS_PUBLIC_KEY = "zL7lT3h0aygc_IS_H";
const DEFAULT_EMAILJS_PRIVATE_KEY = "cqexJMeEoOTN2KfQzomSG";
const DEFAULT_NOTIFY_EMAIL = "sufiangsufiang50@gmail.com"; // order notifications are sent here — override with env.NOTIFY_EMAIL in Cloudflare dashboard if needed
// ⚠️ Set env.SESSION_SECRET in the Cloudflare dashboard (Worker → Settings → Variables → add
// a long random string, keep it secret) — used to sign login session cookies. A default is
// used as a fallback so login still works if you forget, but you should set your own.

// Receiving-account details shown to the customer on the payment page for each method.
// ⚠️ REPLACE these with your real account details, or set the matching env vars in the
// Cloudflare dashboard (JAZZCASH_NUMBER, JAZZCASH_TITLE, EASYPAISA_NUMBER, EASYPAISA_TITLE,
// BANK_NAME, BANK_TITLE, BANK_ACCOUNT) so you don't have to edit code to update them.
const PAYMENT_METHODS = (env) => ([
  {
    id: "jazzcash",
    label: "JazzCash",
    logo: "/images/jazzcash-logo.png",
    color: "#e2001a",
    accountLabel: "JazzCash Number",
    accountNumber: (env && env.JAZZCASH_NUMBER) || "0300-0000000",
    accountTitle: (env && env.JAZZCASH_TITLE) || "SJsubs",
    senderLabel: "Your JazzCash Number (sender)"
  },
  {
    id: "easypaisa",
    label: "EasyPaisa",
    logo: "/images/easypaisa-logo.png",
    color: "#1e7a3c",
    accountLabel: "EasyPaisa Number",
    accountNumber: (env && env.EASYPAISA_NUMBER) || "0300-0000000",
    accountTitle: (env && env.EASYPAISA_TITLE) || "SJsubs",
    senderLabel: "Your EasyPaisa Number (sender)"
  },
  {
    id: "bank",
    label: (env && env.BANK_NAME) || "Meezan Bank",
    logo: "/images/meezan-logo.png",
    color: "#046a38",
    accountLabel: "Account / IBAN",
    accountNumber: (env && env.BANK_ACCOUNT) || "PK00 MEZN 0000 0000 0000 0000",
    accountTitle: (env && env.BANK_TITLE) || "SJsubs",
    senderLabel: "Your Account / IBAN (sender)"
  }
]);

// ========== COMMON CSS ==========
const COMMON_CSS = `
  :root{
    --bg:#FAFAFA; --surface:#FFFFFF; --ink:#14141A; --muted:#6B6B76;
    --line:#E7E7EC; --primary:#15161C; --primary-dark:#000000;
    --primary-light:#F1F1F4; --accent:#2B6CB0; --accent-dark:#1E4E8C;
    --accent-light:#EAF1FB; --danger:#D64545; --success:#1E8E5A;
    --whatsapp:#25D366; --whatsapp-dark:#1DA851;
    --radius:14px; --shadow:0 4px 16px rgba(20,20,26,.06);
    --shadow-lg:0 16px 40px rgba(20,20,26,.12);
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:'Inter',system-ui,-apple-system,'Segoe UI',Arial,sans-serif;
    background:var(--bg); color:var(--ink); line-height:1.5;
    -webkit-font-smoothing:antialiased; min-height:100vh;
    display:flex; flex-direction:column;
  }
  a{text-decoration:none;color:inherit}
  ul{list-style:none}
  img{max-width:100%;display:block}
  button{font:inherit;cursor:pointer;border:none}
  .container{max-width:1200px;margin:0 auto;padding:0 20px;width:100%}

  .page-header{
    background:var(--surface); border-bottom:1px solid var(--line);
    position:sticky; top:0; z-index:50; padding:14px 20px;
  }
  .header-inner{
    display:flex; align-items:center; gap:18px;
    max-width:1200px; margin:0 auto;
  }
  .back-btn{
    width:46px; height:46px; border-radius:50%;
    background:var(--primary-light); color:var(--ink);
    display:flex; align-items:center; justify-content:center;
    font-size:17px; transition:.2s; flex-shrink:0;
    border:1px solid var(--line); cursor:pointer;
  }
  .back-btn:hover{background:var(--line); transform:translateX(-2px);}
  .back-btn i{font-size:15px;}
  .header-logo{height:48px; width:auto; max-width:200px; object-fit:contain;}
  .header-title{
    font-size:16.5px; font-weight:700; color:var(--ink);
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    flex:1; min-width:0;
  }

  main{flex:1; width:100%;}
  .section{padding:36px 0;}

  .breadcrumb{
    display:flex; align-items:center; gap:8px; font-size:13px;
    color:var(--muted); margin-bottom:18px; flex-wrap:wrap;
  }
  .breadcrumb a{color:var(--accent); font-weight:600;}
  .breadcrumb a:hover{text-decoration:underline;}
  .breadcrumb i{font-size:10px; color:var(--line);}

  .page-head{
    display:flex; justify-content:space-between; align-items:flex-end;
    margin-bottom:26px; flex-wrap:wrap; gap:12px;
  }
  .page-head h1{font-size:27px; font-weight:800;}
  .page-head .count{color:var(--muted); font-size:14px; font-weight:500; margin-top:4px;}

  .prod-grid{
    display:grid; grid-template-columns:repeat(4,1fr); gap:20px;
  }
  .prod-empty{
    grid-column:1/-1; text-align:center; padding:60px 20px;
    color:var(--muted); border:1.5px dashed var(--line);
    border-radius:var(--radius); font-size:14px;
  }
  .prod-card{
    background:var(--surface); border:1px solid var(--line);
    border-radius:var(--radius); overflow:hidden; transition:.2s;
    position:relative; cursor:pointer; display:flex; flex-direction:column;
  }
  .prod-card:hover{box-shadow:var(--shadow-lg); transform:translateY(-4px); border-color:transparent;}
  .prod-thumb{
    height:200px; display:flex; align-items:center; justify-content:center;
    overflow:hidden; background:linear-gradient(135deg,var(--primary-light),#F5F5F5);
    flex-shrink:0; position:relative;
  }
  .prod-thumb img{width:100%;height:100%;object-fit:cover;}
  .prod-thumb .fallback-ic{font-size:48px;color:var(--muted);}
  .prod-card .sale{
    position:absolute; top:12px; left:12px;
    background:var(--danger); color:#fff; font-size:11px;
    font-weight:800; padding:4px 10px; border-radius:7px; z-index:2;
  }
  .quick-actions{
    position:absolute; bottom:10px; right:10px; z-index:3;
    display:flex; gap:8px;
  }
  .qa-btn{
    width:34px; height:34px; border-radius:50%;
    background:rgba(255,255,255,.96); border:1px solid var(--line);
    display:flex; align-items:center; justify-content:center;
    font-size:14px; color:var(--ink); transition:.15s; cursor:pointer;
    box-shadow:0 2px 10px rgba(20,20,26,.16); flex-shrink:0;
  }
  .qa-btn:hover{background:var(--ink); color:#fff; border-color:var(--ink); transform:translateY(-2px);}
  .qa-btn.wish.active{background:var(--danger); border-color:var(--danger); color:#fff;}
  .qa-btn.add.added{background:var(--success); border-color:var(--success); color:#fff;}
  .prod-body{padding:16px; flex:1; display:flex; flex-direction:column;}
  .prod-cat{
    color:var(--accent); font-size:11.5px; font-weight:700;
    text-transform:uppercase; letter-spacing:.4px;
  }
  .prod-body h3{
    font-size:15px; margin:6px 0 8px; font-weight:700;
    min-height:38px; display:-webkit-box; -webkit-line-clamp:2;
    -webkit-box-orient:vertical; overflow:hidden;
  }
  .stars{color:#E3A008; font-size:12.5px; margin-bottom:8px; display:flex; align-items:center; gap:2px;}
  .stars .count{color:var(--muted); font-size:11.5px; margin-left:3px;}
  .prod-price{display:flex; align-items:baseline; gap:8px; margin-top:auto; margin-bottom:14px;}
  .prod-price .now{font-weight:800; font-size:17.5px; color:var(--ink);}
  .prod-price .was{color:var(--muted); text-decoration:line-through; font-size:13px;}

  /* ===== BIG, CLEAR ACTION BUTTONS ===== */
  .btn-lg{
    width:100%; background:var(--primary); color:#fff;
    padding:15px 20px; border-radius:12px; font-weight:800; font-size:14.5px;
    transition:.2s; display:flex; align-items:center; justify-content:center; gap:8px;
    cursor:pointer; border:none; font-family:inherit; letter-spacing:.2px;
  }
  .btn-lg:hover{background:var(--primary-dark); transform:translateY(-2px); box-shadow:0 10px 22px rgba(0,0,0,.18);}
  .btn-lg.added{background:var(--success);}

  /* ===== RELATED PRODUCTS ===== */
  .related-section{margin-top:56px;}
  .related-title{font-size:21px; font-weight:800; margin-bottom:20px;}

  /* ===== REVIEWS ===== */
  .reviews-section{margin-top:56px; max-width:820px;}
  .reviews-title{font-size:21px; font-weight:800; margin-bottom:20px;}
  .review-form-box{
    background:var(--surface); border:1px solid var(--line); border-radius:var(--radius);
    padding:22px; margin-bottom:26px;
  }
  .review-form-box h3{font-size:16px; font-weight:800; margin-bottom:14px;}
  .review-form-row{display:flex; gap:12px; margin-bottom:12px; flex-wrap:wrap;}
  .review-form-row input, .review-form-row select, .review-form-box textarea{
    font:inherit; padding:11px 13px; border:1.5px solid var(--line);
    border-radius:10px; background:var(--bg); color:var(--ink); outline:none;
  }
  .review-form-row input:focus, .review-form-row select:focus, .review-form-box textarea:focus{border-color:var(--accent);}
  .review-form-row input{flex:1; min-width:160px;}
  .review-form-row select{flex-shrink:0;}
  .review-form-box textarea{width:100%; resize:vertical; margin-bottom:14px;}
  .review-msg{font-size:13px; margin-top:10px; font-weight:600;}
  .review-msg.success{color:var(--success);}
  .review-msg.error{color:var(--danger);}
  .reviews-list{display:flex; flex-direction:column; gap:14px;}
  .review-item{
    background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:16px 18px;
  }
  .review-top{display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:2px;}
  .review-name{font-weight:700; font-size:14px;}
  .review-stars{font-size:12px;}
  .review-date{color:var(--muted); font-size:12px; margin-bottom:8px;}
  .review-comment{font-size:14px; line-height:1.6; color:var(--ink);}
  .reviews-empty, .reviews-loading{color:var(--muted); font-size:14px; padding:16px 0;}
  .reviews-toggle-btn{
    display:flex; align-items:center; justify-content:center; gap:8px;
    width:100%; background:var(--surface); color:var(--ink);
    border:1.5px solid var(--line); border-radius:12px; padding:12px 20px;
    font-weight:700; font-size:13.5px; transition:.2s;
  }
  .reviews-toggle-btn:hover{background:var(--primary-light);}

  .product-detail{
    display:grid; grid-template-columns:1fr 1fr; gap:44px; align-items:start;
  }
  .product-image{
    background:var(--surface); border-radius:var(--radius);
    overflow:hidden; border:1px solid var(--line);
    display:flex; align-items:center; justify-content:center;
    min-height:420px; background:linear-gradient(135deg,var(--primary-light),#F5F5F5);
    position:sticky; top:90px;
  }
  .product-image img{width:100%; height:100%; object-fit:cover; max-height:520px;}
  .product-image .no-img{font-size:80px; color:var(--muted);}
  .product-info h1{font-size:29px; font-weight:800; margin-bottom:8px; line-height:1.25;}
  .product-info .cat-line{
    color:var(--accent); font-size:13px; font-weight:700;
    text-transform:uppercase; letter-spacing:.4px; margin-bottom:6px;
  }
  .product-info .cat-group{
    display:inline-block; padding:5px 12px; border-radius:999px;
    background:var(--primary-light); color:var(--ink);
    font-size:11.5px; font-weight:700; margin-bottom:14px;
  }
  .product-info .detail-price{display:flex; align-items:baseline; gap:10px; margin-bottom:12px;}
  .product-info .detail-price .now{font-size:30px; font-weight:800;}
  .product-info .detail-price .was{font-size:17px; color:var(--muted); text-decoration:line-through;}
  .product-info .detail-badge{
    display:inline-block; background:var(--danger); color:#fff;
    font-size:12.5px; font-weight:800; padding:6px 14px; border-radius:8px; margin-bottom:14px;
  }
  .product-info .detail-rating{display:flex; align-items:center; gap:8px; margin-bottom:16px;}
  .product-info .detail-rating .stars{font-size:16px; margin-bottom:0;}
  .product-info .detail-rating .rev{color:var(--muted); font-size:13px;}
  .product-info .detail-desc{
    font-size:14.5px; color:var(--ink); line-height:1.7; margin-bottom:22px;
    padding:18px; background:var(--primary-light); border-radius:var(--radius);
  }
  .product-info .detail-features{margin-bottom:24px;}
  .product-info .detail-features h4{font-size:15.5px; font-weight:700; margin-bottom:12px;}
  .product-info .detail-features ul{list-style:none; display:flex; flex-direction:column; gap:10px;}
  .product-info .detail-features li{
    font-size:14.5px; display:flex; align-items:flex-start; gap:10px; color:var(--ink);
  }
  .product-info .detail-features li i{color:var(--success); margin-top:2px; flex-shrink:0;}

  .detail-actions{display:flex; flex-direction:column; gap:12px;}
  .duration-select-wrap{display:flex; flex-direction:column; gap:8px;}
  .duration-select-wrap label{
    font-size:13px; font-weight:700; color:var(--ink);
    display:flex; align-items:center; gap:7px;
  }
  .duration-select-wrap label i{color:var(--accent); font-size:13px;}
  .duration-select{
    appearance:none; -webkit-appearance:none; -moz-appearance:none;
    width:100%; padding:14px 40px 14px 16px; border-radius:12px;
    border:1.5px solid var(--line); background:var(--surface);
    color:var(--ink); font-size:15px; font-weight:700; cursor:pointer;
    transition:.2s;
    background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%236B6B76' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'><polyline points='6 9 12 15 18 9'></polyline></svg>");
    background-repeat:no-repeat; background-position:right 16px center;
  }
  .duration-select:hover, .duration-select:focus{border-color:var(--accent); outline:none;}
  .detail-actions-row{display:flex; align-items:stretch; gap:10px;}
  .btn-order-big{
    display:flex; align-items:center; justify-content:center; gap:10px;
    background:var(--primary); color:#fff; padding:18px 28px;
    border-radius:14px; font-weight:800; font-size:17px;
    transition:transform .2s, box-shadow .2s; flex:1; min-width:0;
  }
  .btn-order-big:hover{transform:translateY(-2px); box-shadow:0 14px 30px rgba(0,0,0,.28);}
  .btn-order-big small{font-weight:600; opacity:.75; font-size:13px;}
  .detail-icon-btn{
    width:54px; flex-shrink:0; border-radius:14px;
    background:var(--surface); color:var(--ink); border:1.5px solid var(--line);
    display:flex; align-items:center; justify-content:center; font-size:18px;
    transition:.2s; cursor:pointer;
  }
  .detail-icon-btn:hover{background:var(--primary-light); transform:translateY(-2px);}
  .detail-icon-btn.added{background:var(--success); border-color:var(--success); color:#fff;}
  .detail-icon-btn.wish.active{background:var(--danger); border-color:var(--danger); color:#fff;}

  .btn-home{
    display:inline-flex; align-items:center; gap:10px;
    background:var(--primary); color:#fff; padding:16px 30px;
    border-radius:999px; font-weight:800; font-size:15px; transition:.2s;
  }
  .btn-home:hover{transform:translateY(-2px); box-shadow:0 10px 24px rgba(0,0,0,.2);}
  .btn-outline{
    display:inline-flex; align-items:center; gap:10px;
    background:var(--surface); color:var(--ink); padding:15px 28px;
    border-radius:999px; font-weight:800; font-size:15px;
    border:1.5px solid var(--line); transition:.2s;
  }
  .btn-outline:hover{background:var(--primary-light);}

  .floating-side{
    position:fixed; right:24px; bottom:24px; z-index:60;
    display:flex; flex-direction:column; align-items:center; gap:12px;
  }
  .float-action-btn{
    width:50px; height:50px; border-radius:50%;
    background:var(--surface); color:var(--ink);
    display:flex; align-items:center; justify-content:center;
    font-size:19px; box-shadow:0 4px 14px rgba(20,20,26,.14);
    border:1.5px solid var(--line); position:relative; transition:transform .2s;
    cursor:pointer;
  }
  .float-action-btn:hover{transform:translateY(-2px);}
  .float-action-btn .float-badge{
    position:absolute; top:-6px; right:-6px;
    background:var(--accent); color:#fff; font-size:10px; font-weight:700;
    width:19px; height:19px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
  }

  .toast-wrap{
    position:fixed; bottom:100px; left:50%; transform:translateX(-50%);
    z-index:120; display:flex; flex-direction:column; gap:8px; align-items:center;
    pointer-events:none;
  }
  .toast{
    background:var(--ink); color:#fff; padding:12px 22px;
    border-radius:999px; font-size:13.5px; font-weight:600;
    display:flex; align-items:center; gap:8px;
    box-shadow:var(--shadow-lg); opacity:0; transform:translateY(10px);
    transition:.25s; white-space:nowrap;
  }
  .toast.show{opacity:1; transform:translateY(0);}
  .toast i{color:var(--success);}

  /* ===== CHECKOUT / PAYMENT PAGE ===== */
  .checkout-wrap{max-width:640px; margin:0 auto;}
  .checkout-card{
    background:var(--surface); border:1px solid var(--line); border-radius:var(--radius);
    overflow:hidden; margin-bottom:24px;
  }
  .checkout-prod{display:flex; gap:16px; padding:20px; border-bottom:1px solid var(--line);}
  .checkout-prod .thumb{
    width:88px; height:88px; border-radius:12px; overflow:hidden; flex-shrink:0;
    background:linear-gradient(135deg,var(--primary-light),#F5F5F5);
    display:flex; align-items:center; justify-content:center;
  }
  .checkout-prod .thumb img{width:100%;height:100%;object-fit:cover;}
  .checkout-prod .thumb i{font-size:30px; color:var(--muted);}
  .checkout-prod .info h3{font-size:16.5px; font-weight:800; margin-bottom:4px;}
  .checkout-prod .info .cat{color:var(--accent); font-size:12px; font-weight:700; text-transform:uppercase; margin-bottom:8px;}
  .checkout-prod .info .price{display:flex; align-items:baseline; gap:8px;}
  .checkout-prod .info .price .now{font-size:19px; font-weight:800;}
  .checkout-prod .info .price .was{font-size:13px; color:var(--muted); text-decoration:line-through;}
  .checkout-rows{padding:18px 20px;}
  .checkout-row{display:flex; justify-content:space-between; align-items:center; padding:9px 0; font-size:14px;}
  .checkout-row.total{border-top:1px dashed var(--line); margin-top:6px; padding-top:14px; font-size:17px; font-weight:800;}
  .checkout-row .lbl{color:var(--muted);}
  .checkout-note{
    display:flex; gap:10px; align-items:flex-start; background:var(--accent-light);
    color:var(--accent-dark); padding:14px 16px; border-radius:12px; font-size:13.5px;
    margin-bottom:20px; line-height:1.6;
  }
  .checkout-note i{margin-top:2px; flex-shrink:0;}
  .btn-whatsapp{
    display:flex; align-items:center; justify-content:center; gap:12px;
    background:var(--whatsapp); color:#fff; padding:19px 28px;
    border-radius:14px; font-weight:800; font-size:17px; width:100%;
    transition:.2s; box-shadow:0 10px 24px rgba(37,211,102,.28);
  }
  .btn-whatsapp:hover{background:var(--whatsapp-dark); transform:translateY(-2px);}
  .btn-whatsapp i{font-size:22px;}
  .btn-whatsapp-sm{padding:12px 18px; font-size:14px; font-weight:700; gap:8px;}
  .btn-whatsapp-sm i.fa-whatsapp{font-size:18px;}
  .wa-dropdown-wrap{position:relative; width:100%;}
  .wa-dropdown-menu{
    display:none; position:absolute; left:0; right:0; bottom:calc(100% + 8px);
    background:var(--surface); border:1.5px solid var(--line); border-radius:12px;
    box-shadow:0 10px 28px rgba(0,0,0,.14); overflow:hidden; z-index:30;
  }
  .wa-dropdown-menu.show{display:block;}
  .wa-dropdown-item{
    display:flex; align-items:center; gap:10px; width:100%; padding:13px 16px;
    background:none; text-align:left; font-size:14.5px; font-weight:700; color:var(--ink);
  }
  .wa-dropdown-item + .wa-dropdown-item{border-top:1px solid var(--line);}
  .wa-dropdown-item:hover{background:var(--primary-light);}
  .wa-dropdown-item i{color:var(--whatsapp); font-size:17px;}
  .checkout-empty{
    text-align:center; padding:60px 20px; color:var(--muted);
  }
  .checkout-empty i{font-size:48px; margin-bottom:14px; display:block; color:var(--line);}

  /* ===== PAYMENT METHOD + ORDER FORM ===== */
  .pay-section-title{font-size:13.5px; font-weight:800; color:var(--ink); margin-bottom:12px; display:flex; align-items:center; gap:7px;}
  .pay-section-title i{color:var(--accent); font-size:12px;}
  .pay-methods{margin-bottom:16px;}
  .pay-method-select{
    appearance:none; -webkit-appearance:none; -moz-appearance:none;
    width:100%; padding:14px 40px 14px 16px; border-radius:12px;
    border:1.5px solid var(--line); background:var(--surface);
    color:var(--ink); font-size:15px; font-weight:700; cursor:pointer;
    transition:.2s;
    background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%236B6B76' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'><polyline points='6 9 12 15 18 9'></polyline></svg>");
    background-repeat:no-repeat; background-position:right 16px center;
  }
  .pay-method-select:hover, .pay-method-select:focus{border-color:var(--accent); outline:none;}

  .pay-account-box{background:var(--primary-light); border-radius:12px; padding:14px 16px; margin-bottom:18px; font-size:13px; display:none;}
  .pay-account-box.show{display:block;}
  .pay-account-row{display:flex; justify-content:space-between; align-items:center; padding:4px 0; gap:10px;}
  .pay-account-row .lbl{color:var(--muted); flex-shrink:0;}
  .pay-account-row .val{font-weight:700; word-break:break-all; text-align:right;}
  .copy-btn{
    background:var(--surface); border:1px solid var(--line); border-radius:7px;
    padding:3px 9px; font-size:10.5px; color:var(--accent); cursor:pointer; flex-shrink:0; font-weight:700;
  }
  .copy-btn:hover{background:var(--accent-light);}

  .order-form{display:none; flex-direction:column; gap:14px;}
  .order-form.show{display:flex;}
  .form-group{display:flex; flex-direction:column; gap:6px;}
  .form-group label{font-size:12px; font-weight:700; color:var(--ink);}
  .form-group input[type=text], .form-group input[type=tel], .form-group input[type=email], .form-group input[type=password]{
    padding:12px 14px; border-radius:10px; border:1.5px solid var(--line);
    font-size:14px; background:var(--surface); color:var(--ink); width:100%;
  }
  .form-group input:focus{outline:none; border-color:var(--accent);}
  .form-group input[readonly]{background:var(--primary-light); color:var(--muted);}
  .form-row-2{display:grid; grid-template-columns:1fr 1fr; gap:12px;}

  .auth-tabs{display:flex; gap:8px; margin-bottom:18px; border-bottom:1.5px solid var(--line);}
  .auth-tab-btn{
    flex:1; background:none; padding:12px 10px; font-weight:700; font-size:14px;
    color:var(--muted); border-bottom:2.5px solid transparent; margin-bottom:-1.5px; transition:.15s;
  }
  .auth-tab-btn.active{color:var(--accent); border-bottom-color:var(--accent);}
  .auth-tab-panel.show{display:flex;}

  .upload-box{
    border:1.5px dashed var(--line); border-radius:12px; padding:16px;
    text-align:center; cursor:pointer; transition:.15s; position:relative;
  }
  .upload-box:hover{border-color:var(--accent);}
  .upload-box i{font-size:20px; color:var(--muted); margin-bottom:5px; display:block;}
  .upload-box span{font-size:12px; color:var(--muted);}
  .upload-box.has-file{border-color:var(--success); border-style:solid;}
  .upload-box input[type=file]{position:absolute; inset:0; opacity:0; cursor:pointer;}
  .upload-preview{display:none; margin-top:10px; border-radius:8px; overflow:hidden; max-height:130px;}
  .upload-preview img{width:100%; display:block; object-fit:cover;}

  .btn-submit-order{
    width:100%; background:var(--primary); color:#fff; padding:15px;
    border-radius:12px; font-weight:800; font-size:14px;
    display:flex; align-items:center; justify-content:center; gap:8px; transition:.2s;
  }
  .btn-submit-order:hover{background:var(--primary-dark); transform:translateY(-1px);}
  .btn-submit-order:disabled{opacity:.55; cursor:not-allowed; transform:none;}

  .form-msg{font-size:12px; padding-top:2px;}
  .form-msg.error{color:var(--danger);}
  .form-msg.success{color:var(--success);}

  .order-success{text-align:center; padding:44px 20px;}
  .order-success i{font-size:50px; color:var(--success); margin-bottom:14px; display:block;}
  .order-success h2{font-size:18px; font-weight:800; margin-bottom:8px;}
  .order-success p{color:var(--muted); font-size:13px; line-height:1.65; margin-bottom:22px; max-width:340px; margin-left:auto; margin-right:auto;}

  .pay-divider{border-top:1px dashed var(--line); margin:4px 0 18px;}

  footer{
    background:var(--surface); color:#4D4D4D;
    padding:40px 0; border-top:1px solid var(--line); margin-top:auto;
  }
  .footer-inner{
    max-width:1200px; margin:0 auto; padding:0 20px;
    display:flex; justify-content:center; align-items:center;
    flex-wrap:wrap; gap:10px; font-size:13px; text-align:center;
  }
  .brand-credit{
    display:inline-flex; align-items:center; gap:6px;
  }
  .brand-credit strong{
    color:var(--ink); font-weight:700;
    background:linear-gradient(135deg,var(--accent),var(--accent-dark));
    -webkit-background-clip:text; background-clip:text;
    -webkit-text-fill-color:transparent;
  }

  @media (max-width:980px){.prod-grid{grid-template-columns:repeat(2,1fr);}}
  @media (max-width:768px){
    .product-detail{grid-template-columns:1fr;}
    .product-image{min-height:300px; position:static;}
    .product-info h1{font-size:23px;}
    .page-head h1{font-size:22px;}
  }
  @media (max-width:480px){
    .prod-grid{grid-template-columns:1fr;}
    .section{padding:24px 0;}
    .product-detail{gap:24px;}
    .detail-actions-row .btn-order-big{font-size:15px; padding:16px 18px;}
    .checkout-prod{flex-direction:column; align-items:flex-start;}
  }
`;

// ========== HTML BUILDERS ==========

function buildHeader(fallbackUrl, pageTitle, extraMeta) {
  fallbackUrl = fallbackUrl || "/";
  pageTitle = pageTitle || "";
  extraMeta = extraMeta || "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${pageTitle ? escapeHtml(pageTitle) + " — " : ""}SJsubs — Premium Subscriptions Store</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="icon" type="image/png" href="/images/logo.png">
${extraMeta}
<style>${COMMON_CSS}</style>
</head>
<body>
  <header class="page-header">
    <div class="header-inner">
      <a href="${fallbackUrl}" class="back-btn" id="smartBackBtn" title="Go back" aria-label="Go back">
        <i class="fa-solid fa-arrow-left"></i>
      </a>
      <a href="/"><img src="${LOGO_URL}" alt="SJsubs Logo" class="header-logo" onerror="this.style.display='none'"></a>
      ${pageTitle ? `<span class="header-title">${escapeHtml(pageTitle)}</span>` : ''}
    </div>
  </header>
  <script>
    // Smart back button: goes to the actual previous page in browser history
    // (falls back to homepage only if there's no usable history, e.g. direct link/new tab)
    document.getElementById('smartBackBtn').addEventListener('click', function(e){
      if (document.referrer && document.referrer.indexOf(window.location.host) !== -1 && window.history.length > 1) {
        e.preventDefault();
        window.history.back();
      }
      // otherwise let the href="${fallbackUrl}" take over naturally
    });
  </script>
  <main>`;
}

function buildFooter() {
  return `
  </main>

  <div class="floating-side">
    <a href="/" class="float-action-btn" id="wishlistToggle" aria-label="Wishlist">
      <i class="fa-regular fa-heart"></i>
      <span class="float-badge" id="wishlistCount" style="display:none">0</span>
    </a>
    <a href="/" class="float-action-btn" id="cartToggle" aria-label="Cart">
      <i class="fa-solid fa-bag-shopping"></i>
      <span class="float-badge" id="cartCount" style="display:none">0</span>
    </a>
  </div>

  <div class="toast-wrap" id="toastWrap"></div>

  <footer>
    <div class="footer-inner">
      <span>&copy; ${new Date().getFullYear()} SJsubs — All rights reserved.</span>
      <span class="brand-credit">Powered by <strong>SufianX</strong></span>
    </div>
  </footer>

  <script>
    (function() {
      var CART_KEY = 'sjsubs_cart';
      var WISH_KEY = 'sjsubs_wishlist';

      function getCart() { try { return JSON.parse(localStorage.getItem(CART_KEY)) || []; } catch(e) { return []; } }
      function saveCart(cart) { localStorage.setItem(CART_KEY, JSON.stringify(cart)); updateBadges(); }
      function addToCart(product) {
        var cart = getCart();
        var existing = cart.find(function(i) { return i.id === product.id; });
        if (existing) { existing.qty += 1; }
        else { cart.push({ id: product.id, name: product.name, price: product.price, image: product.image || '', qty: 1 }); }
        saveCart(cart);
        showToast(product.name + ' added to cart');
      }

      function getWishlist() { try { return JSON.parse(localStorage.getItem(WISH_KEY)) || []; } catch(e) { return []; } }
      function saveWishlist(list) { localStorage.setItem(WISH_KEY, JSON.stringify(list)); updateBadges(); }
      function toggleWishlist(product, btnEl) {
        var list = getWishlist();
        var idx = list.findIndex(function(w) { return w.id === product.id; });
        if (idx > -1) {
          list.splice(idx, 1);
          if (btnEl) { btnEl.classList.remove('active'); var ic = btnEl.querySelector('i'); if(ic) ic.className = 'fa-regular fa-heart'; }
          showToast(product.name + ' removed from wishlist');
        } else {
          list.push({ id: product.id, name: product.name, price: product.price, image: product.image || '' });
          if (btnEl) { btnEl.classList.add('active'); var ic2 = btnEl.querySelector('i'); if(ic2) ic2.className = 'fa-solid fa-heart'; }
          showToast(product.name + ' added to wishlist');
        }
        saveWishlist(list);
      }

      function updateBadges() {
        var cartCount = getCart().reduce(function(sum, i) { return sum + i.qty; }, 0);
        var wishCount = getWishlist().length;
        var cartBadge = document.getElementById('cartCount');
        var wishBadge = document.getElementById('wishlistCount');
        if (cartBadge) { cartBadge.textContent = cartCount; cartBadge.style.display = cartCount > 0 ? 'flex' : 'none'; }
        if (wishBadge) { wishBadge.textContent = wishCount; wishBadge.style.display = wishCount > 0 ? 'flex' : 'none'; }
      }

      function showToast(msg) {
        var wrap = document.getElementById('toastWrap');
        if (!wrap) return;
        var t = document.createElement('div');
        t.className = 'toast';
        t.innerHTML = '<i class="fa-solid fa-circle-check"></i>' + msg;
        wrap.appendChild(t);
        requestAnimationFrame(function() { t.classList.add('show'); });
        setTimeout(function() { t.classList.remove('show'); setTimeout(function() { if(t.parentNode) t.remove(); }, 300); }, 2200);
      }

      document.addEventListener('DOMContentLoaded', function() {
        updateBadges();
        var wishlist = getWishlist();
        var wishIds = wishlist.map(function(w) { return w.id; });
        document.querySelectorAll('.prod-card, .product-info').forEach(function(card) {
          var id = card.getAttribute('data-id');
          if (id && wishIds.indexOf(id) > -1) {
            var wishBtn = card.querySelector('[data-action="wish"]');
            if (wishBtn) { wishBtn.classList.add('active'); var ic = wishBtn.querySelector('i'); if(ic) ic.className = 'fa-solid fa-heart'; }
          }
        });
        var ct = document.getElementById('cartToggle');
        var wt = document.getElementById('wishlistToggle');
        if (ct) ct.addEventListener('click', function(e) { e.preventDefault(); window.location.href = '/?open=cart'; });
        if (wt) wt.addEventListener('click', function(e) { e.preventDefault(); window.location.href = '/?open=wishlist'; });
      });

      document.addEventListener('click', function(e) {
        var wishBtn = e.target.closest('[data-action="wish"]');
        if (wishBtn) {
          e.preventDefault(); e.stopPropagation();
          var card = wishBtn.closest('.prod-card, .product-info');
          if (card) toggleWishlist({ id: card.getAttribute('data-id'), name: card.getAttribute('data-name'), price: Number(card.getAttribute('data-price')) || 0, image: card.getAttribute('data-image') || '' }, wishBtn);
          return;
        }
        var addBtn = e.target.closest('[data-action="add"]');
        if (addBtn) {
          e.preventDefault(); e.stopPropagation();
          var card = addBtn.closest('.prod-card, .product-info');
          if (card) {
            addToCart({ id: card.getAttribute('data-id'), name: card.getAttribute('data-name'), price: Number(card.getAttribute('data-price')) || 0, image: card.getAttribute('data-image') || '' });
            addBtn.classList.add('added');
            if (addBtn.classList.contains('qa-btn')) {
              var icon = addBtn.querySelector('i');
              var origIcon = icon ? icon.className : '';
              if (icon) icon.className = 'fa-solid fa-check';
              setTimeout(function() { addBtn.classList.remove('added'); if (icon) icon.className = origIcon; }, 1400);
            } else {
              var origHTML = addBtn.innerHTML;
              addBtn.innerHTML = '<i class="fa-solid fa-check"></i> Added to Cart';
              setTimeout(function() { addBtn.classList.remove('added'); addBtn.innerHTML = origHTML; }, 1400);
            }
          }
          return;
        }
      });
    })();
  </script>
</body>
</html>`;
}

// ========== PAGE BUILDERS ==========

function buildProductCard(p) {
  const thumb = p.image
    ? `<img src="${escapeHtml(p.image)}" alt="${escapeHtml(p.name)}" loading="lazy" onerror="this.parentElement.innerHTML='<div class=\\'fallback-ic\\'><i class=\\'fa-solid fa-image\\'></i></div>'">`
    : `<div class="fallback-ic"><i class="fa-solid fa-image"></i></div>`;

  return `
  <div class="prod-card" data-id="${escapeHtml(p.id || '')}" data-slug="${escapeHtml(p.slug || '')}" data-name="${escapeHtml(p.name || '')}" data-price="${p.price || 0}" data-image="${escapeHtml(p.image || '')}" data-category="${escapeHtml(p.category || '')}">
    ${p.badge ? `<span class="sale">${escapeHtml(p.badge)}</span>` : ''}
    <a href="/product/${encodeURIComponent(p.slug || '')}" class="prod-thumb" style="display:flex;">
      ${thumb}
      <div class="quick-actions">
        <button type="button" class="qa-btn wish" data-action="wish" aria-label="Add to wishlist"><i class="fa-regular fa-heart"></i></button>
        <button type="button" class="qa-btn add" data-action="add" aria-label="Add to cart"><i class="fa-solid fa-bag-shopping"></i></button>
      </div>
    </a>
    <div class="prod-body">
      <a href="/product/${encodeURIComponent(p.slug || '')}" style="text-decoration:none;color:inherit;">
        <div class="prod-cat">${escapeHtml(p.category || '')}</div>
        <h3>${escapeHtml(p.name || 'Untitled Product')}</h3>
        <div class="stars">${starsHTML(p.rating, p.reviews)}</div>
        <div class="prod-price"><span class="now">${money(p.price)}</span>${p.oldPrice ? `<span class="was">${money(p.oldPrice)}</span>` : ''}</div>
      </a>
    </div>
  </div>`;
}

function buildNotFoundPage(title, message) {
  title = title || "Page Not Found";
  message = message || "The page you're looking for doesn't exist or has been removed.";
  let html = buildHeader("/", "");
  html += `<div class="container"><section class="section" style="text-align:center; padding:90px 20px;"><div style="max-width:480px; margin:0 auto;"><div style="font-size:68px; color:var(--muted); margin-bottom:18px; font-weight:200; line-height:1;"><i class="fa-solid fa-box-open"></i></div><h1 style="font-size:23px; font-weight:800; color:var(--ink); margin-bottom:10px;">${escapeHtml(title)}</h1><p style="color:var(--muted); font-size:14.5px; margin-bottom:28px; line-height:1.6;">${escapeHtml(message)}</p><div style="display:flex; gap:14px; justify-content:center; flex-wrap:wrap;"><a href="/" class="btn-home"><i class="fa-solid fa-house"></i> Back to Home</a><a href="/all-products" class="btn-outline"><i class="fa-solid fa-grid-2"></i> All Products</a></div></div></section></div>`;
  html += buildFooter();
  return html;
}

function buildEmptyCategoryPage(categoryName) {
  const catName = decodeURIComponent(categoryName);
  let html = buildHeader("/", catName);
  html += `<div class="container"><section class="section" style="text-align:center; padding:90px 20px;"><div style="max-width:480px; margin:0 auto;"><div style="font-size:58px; color:var(--line); margin-bottom:14px; font-weight:200; line-height:1;"><i class="fa-solid fa-folder-open"></i></div><h1 style="font-size:21px; font-weight:800; color:var(--ink); margin-bottom:10px;">${escapeHtml(catName)}</h1><p style="color:var(--muted); font-size:14.5px; margin-bottom:28px; line-height:1.6;">No products are available in this category at the moment. Please check back later or browse other categories.</p><div style="display:flex; gap:14px; justify-content:center; flex-wrap:wrap;"><a href="/" class="btn-home"><i class="fa-solid fa-house"></i> Home</a><a href="/all-products" class="btn-outline"><i class="fa-solid fa-grid-2"></i> All Products</a></div></div></section></div>`;
  html += buildFooter();
  return html;
}

function buildCategoryPage(categoryName, products) {
  const catName = decodeURIComponent(categoryName);
  let html = buildHeader("/", catName);
  html += `<div class="container"><section class="section">
    <div class="breadcrumb"><a href="/">Home</a><i class="fa-solid fa-chevron-right"></i><span>${escapeHtml(catName)}</span></div>
    <div class="page-head"><div><h1>${escapeHtml(catName)}</h1><div class="count">${products.length} product${products.length !== 1 ? 's' : ''}</div></div></div>`;
  if (products.length === 0) { html += `<div class="prod-empty">No products found in this category.</div>`; }
  else { html += `<div class="prod-grid">${products.map(buildProductCard).join('')}</div>`; }
  html += `</section></div>` + buildFooter();
  return html;
}

function buildProductDetailPage(product, siteUrl, relatedProducts) {
  relatedProducts = relatedProducts || [];
  const title = product.name || 'Product';

  // ===== Subscription duration options =====
  // Expected on the product doc (set from the admin panel): product.durations = [{ label: "1 Month", price: 999 }, { label: "6 Months", price: 4999 }, { label: "1 Year", price: 8999 }]
  // Falls back to a single "Standard" option using product.price if no durations are set (keeps old products working).
  const durations = (Array.isArray(product.durations) && product.durations.length > 0)
    ? product.durations.filter(d => d && d.label)
    : [{ label: "Standard", price: product.price || 0 }];

  const durationOptionsHtml = durations.map((d, i) =>
    `<option value="${i}" data-price="${Number(d.price) || 0}"${i === 0 ? ' selected' : ''}>${escapeHtml(d.label)} — ${money(d.price)}</option>`
  ).join('');

  const defaultOrderUrl = `/payment.html?${new URLSearchParams({
    name: product.name || '', price: durations[0].price || 0, oldPrice: product.oldPrice || '',
    image: product.image || '', category: product.category || '', slug: product.slug || '',
    duration: durations[0].label || ''
  }).toString()}`;

  const metaTitle = product.metaTitle || product.name || '';
  const metaDesc = (product.metaDescription || product.description || '').substring(0, 160);
  const canonicalUrl = `${siteUrl}/product/${encodeURIComponent(product.slug || '')}`;
  const extraMeta = `<meta name="description" content="${escapeHtml(metaDesc)}"><meta name="keywords" content="${escapeHtml(product.metaKeywords || product.category || '')}"><meta property="og:title" content="${escapeHtml(metaTitle)}"><meta property="og:description" content="${escapeHtml(metaDesc)}">${product.image ? `<meta property="og:image" content="${escapeHtml(product.image)}">` : ''}<meta property="og:type" content="product"><meta property="og:url" content="${canonicalUrl}"><link rel="canonical" href="${canonicalUrl}">`;

  let html = buildHeader("/", title, extraMeta);
  html += `<div class="container"><section class="section">
    <div class="breadcrumb"><a href="/">Home</a><i class="fa-solid fa-chevron-right"></i><a href="/category/${encodeURIComponent(product.category || '')}">${escapeHtml(product.category || '')}</a><i class="fa-solid fa-chevron-right"></i><span>${escapeHtml(product.name || '')}</span></div>
    <div class="product-detail">
      <div class="product-image">${product.image ? `<img src="${escapeHtml(product.image)}" alt="${escapeHtml(product.name)}" onerror="this.parentElement.innerHTML='<div class=\\'no-img\\'><i class=\\'fa-solid fa-image\\'></i></div>'">` : `<div class="no-img"><i class="fa-solid fa-image"></i></div>`}</div>
      <div class="product-info" data-id="${escapeHtml(product.id || '')}" data-name="${escapeHtml(product.name || '')}" data-price="${product.price || 0}" data-image="${escapeHtml(product.image || '')}">
        <div class="cat-line">${escapeHtml(product.category || '')}</div>
        ${product.categoryGroup ? `<div class="cat-group">${escapeHtml(product.categoryGroup)}</div>` : ''}
        <h1>${escapeHtml(product.name || 'Untitled Product')}</h1>
        <div class="detail-rating"><div class="stars">${starsHTML(product.rating, product.reviews)}</div>${product.reviews ? `<span class="rev">(${product.reviews} reviews)</span>` : ''}</div>
        <div class="detail-price"><span class="now" id="mainPriceNow">${money(durations[0].price)}</span>${product.oldPrice ? `<span class="was" id="mainPriceWas">${money(product.oldPrice)}</span>` : ''}</div>
        ${product.badge ? `<span class="detail-badge">${escapeHtml(product.badge)}</span>` : ''}
        <div class="detail-desc">${escapeHtml(product.description || 'No description available.')}</div>
        ${product.details ? `<div class="detail-features"><h4>Features & Details</h4><ul>${product.details.split('\\n').filter(l => l.trim()).map(l => `<li><i class="fa-solid fa-circle-check"></i> ${escapeHtml(l.trim().replace(/^[✔✅•\\-]\\s*/, ''))}</li>`).join('')}</ul></div>` : ''}
        <div class="detail-actions">
          <div class="duration-select-wrap">
            <label for="durationSelect"><i class="fa-solid fa-calendar-days"></i> Select Subscription Duration</label>
            <select id="durationSelect" class="duration-select">${durationOptionsHtml}</select>
          </div>
          <div class="detail-actions-row">
            <a href="${defaultOrderUrl}" id="orderNowBtn" class="btn-order-big"><i class="fa-solid fa-bolt"></i> Order Now</a>
            <button type="button" class="detail-icon-btn qa-btn add" data-action="add" aria-label="Add to cart"><i class="fa-solid fa-bag-shopping"></i></button>
            <button type="button" class="detail-icon-btn qa-btn wish" data-action="wish" aria-label="Wishlist"><i class="fa-regular fa-heart"></i></button>
          </div>
        </div>
      </div>
    </div>

    ${relatedProducts.length > 0 ? `<div class="related-section">
      <h2 class="related-title">Related Products</h2>
      <div class="prod-grid">${relatedProducts.map(buildProductCard).join('')}</div>
    </div>` : ''}

    <div class="reviews-section" data-slug="${escapeHtml(product.slug || '')}">
      <h2 class="reviews-title">Customer Reviews</h2>
      <div class="review-form-box">
        <h3>Write a Review</h3>
        <div class="review-form-row">
          <input type="text" id="reviewName" placeholder="Your name" maxlength="60">
          <input type="email" id="reviewEmail" placeholder="Your email" maxlength="120">
          <select id="reviewRating">
            <option value="5">★★★★★ (5)</option>
            <option value="4">★★★★☆ (4)</option>
            <option value="3">★★★☆☆ (3)</option>
            <option value="2">★★☆☆☆ (2)</option>
            <option value="1">★☆☆☆☆ (1)</option>
          </select>
        </div>
        <textarea id="reviewComment" placeholder="Share your experience with this product..." maxlength="500" rows="3"></textarea>
        <button type="button" id="submitReviewBtn" class="btn-lg" style="width:auto;padding:12px 26px;"><i class="fa-solid fa-paper-plane"></i> Submit Review</button>
        <div id="reviewMsg" class="review-msg"></div>
      </div>
      <div id="reviewsList" class="reviews-list">
        <div class="reviews-loading">Loading reviews…</div>
      </div>
    </div>
  </section></div>
  <script>
  (function(){
    var slug = ${JSON.stringify(product.slug || '')};

    // ===== Duration selector + dynamic Order Now =====
    function fmtMoney(n){ return "₨" + Number(n || 0).toLocaleString(); }
    var productBase = {
      name: ${JSON.stringify(product.name || '')},
      oldPrice: ${JSON.stringify(product.oldPrice || '')},
      image: ${JSON.stringify(product.image || '')},
      category: ${JSON.stringify(product.category || '')},
      slug: ${JSON.stringify(product.slug || '')}
    };
    var durationSelect = document.getElementById('durationSelect');
    var mainPriceNow = document.getElementById('mainPriceNow');
    var mainPriceWas = document.getElementById('mainPriceWas');
    var orderNowBtn = document.getElementById('orderNowBtn');

    function selectedOption(){
      return durationSelect ? durationSelect.options[durationSelect.selectedIndex] : null;
    }
    function selectedPrice(){
      var opt = selectedOption();
      return opt ? (Number(opt.getAttribute('data-price')) || 0) : 0;
    }
    function selectedLabel(){
      var opt = selectedOption();
      return opt ? opt.textContent.split(' — ')[0] : '';
    }
    function updatePriceDisplay(){
      if (mainPriceNow) mainPriceNow.textContent = fmtMoney(selectedPrice());
      // The old/strikethrough price only applies to the default (first) duration —
      // hide it once the user picks a different duration, since we don't have a
      // per-duration "was" price to compare against.
      if (mainPriceWas) mainPriceWas.style.display = (durationSelect && durationSelect.selectedIndex === 0) ? '' : 'none';
    }
    if (durationSelect) {
      durationSelect.addEventListener('change', function(){
        updatePriceDisplay();
        updateOrderLink();
      });
    }
    function updateOrderLink(){
      if (!orderNowBtn) return;
      var qs = new URLSearchParams({
        name: productBase.name,
        price: selectedPrice(),
        oldPrice: productBase.oldPrice,
        image: productBase.image,
        category: productBase.category,
        slug: productBase.slug,
        duration: selectedLabel()
      }).toString();
      orderNowBtn.setAttribute('href', '/payment.html?' + qs);
    }
    updateOrderLink();
    updatePriceDisplay();

    var listEl = document.getElementById('reviewsList');
    function esc(s){ var d=document.createElement('div'); d.textContent = (s===null||s===undefined)?'':String(s); return d.innerHTML; }
    function starsFor(n){
      n = Math.max(1, Math.min(5, Number(n) || 5));
      var h = '';
      for (var i=1;i<=5;i++){ h += '<i class="fa-solid fa-star" style="color:' + (i<=n?'#E3A008':'#E7E7EC') + '"></i>'; }
      return h;
    }
    var REVIEWS_PREVIEW_COUNT = 2;
    var reviewsExpanded = false;

    function renderReviews(list){
      if (!listEl) return;
      if (!list || list.length===0){
        listEl.innerHTML = '<div class="reviews-empty">No reviews yet. Be the first to review this product!</div>';
        return;
      }
      var visible = reviewsExpanded ? list : list.slice(0, REVIEWS_PREVIEW_COUNT);
      var itemsHtml = visible.map(function(r){
        var d = r.createdAt ? new Date(r.createdAt).toLocaleDateString() : '';
        return '<div class="review-item"><div class="review-top"><span class="review-name">' + esc(r.name || 'Anonymous') + '</span><span class="review-stars">' + starsFor(r.rating) + '</span></div><div class="review-date">' + esc(d) + '</div><div class="review-comment">' + esc(r.comment || '') + '</div></div>';
      }).join('');

      var toggleHtml = '';
      if (list.length > REVIEWS_PREVIEW_COUNT) {
        toggleHtml = reviewsExpanded
          ? '<button type="button" id="reviewsToggleBtn" class="reviews-toggle-btn">Show less <i class="fa-solid fa-chevron-up"></i></button>'
          : '<button type="button" id="reviewsToggleBtn" class="reviews-toggle-btn">Show all ' + list.length + ' reviews <i class="fa-solid fa-chevron-down"></i></button>';
      }

      listEl.innerHTML = itemsHtml + toggleHtml;

      var toggleBtn = document.getElementById('reviewsToggleBtn');
      if (toggleBtn) {
        toggleBtn.addEventListener('click', function(){
          reviewsExpanded = !reviewsExpanded;
          renderReviews(list);
        });
      }
    }
    function loadReviews(){
      fetch('/api/reviews/' + encodeURIComponent(slug))
        .then(function(r){ return r.json(); })
        .then(function(data){ renderReviews(data.reviews || []); })
        .catch(function(){ if (listEl) listEl.innerHTML = '<div class="reviews-empty">Could not load reviews right now.</div>'; });
    }
    var submitBtn = document.getElementById('submitReviewBtn');
    if (submitBtn) {
      submitBtn.addEventListener('click', function(){
        var nameEl = document.getElementById('reviewName');
        var emailEl = document.getElementById('reviewEmail');
        var ratingEl = document.getElementById('reviewRating');
        var commentEl = document.getElementById('reviewComment');
        var msgEl = document.getElementById('reviewMsg');
        var name = nameEl.value.trim();
        var email = emailEl.value.trim();
        var comment = commentEl.value.trim();
        if (!name || !email || !comment) {
          msgEl.textContent = 'Please enter your name, email and a comment.';
          msgEl.className = 'review-msg error';
          return;
        }
        if (email.indexOf('@') === -1 || email.indexOf('.') === -1) {
          msgEl.textContent = 'Please enter a valid email address.';
          msgEl.className = 'review-msg error';
          return;
        }
        submitBtn.disabled = true;
        fetch('/api/review', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ slug: slug, name: name, email: email, rating: Number(ratingEl.value), comment: comment })
        })
          .then(function(r){ return r.json(); })
          .then(function(res){
            submitBtn.disabled = false;
            if (res && res.success) {
              msgEl.textContent = 'Thanks! Your review has been submitted.';
              msgEl.className = 'review-msg success';
              nameEl.value = ''; emailEl.value = ''; commentEl.value = '';
              loadReviews();
            } else {
              msgEl.textContent = (res && res.error) || 'Something went wrong. Please try again.';
              msgEl.className = 'review-msg error';
            }
          })
          .catch(function(){
            submitBtn.disabled = false;
            msgEl.textContent = 'Network error. Please try again.';
            msgEl.className = 'review-msg error';
          });
      });
    }
    loadReviews();
  })();
  </script>`;
  html += buildFooter();
  return html;
}

function buildAllProductsPage(products) {
  let html = buildHeader("/", "All Products");
  html += `<div class="container"><section class="section">
    <div class="breadcrumb"><a href="/">Home</a><i class="fa-solid fa-chevron-right"></i><span>All Products</span></div>
    <div class="page-head"><div><h1>All Products</h1><div class="count">${products.length} product${products.length !== 1 ? 's' : ''}</div></div></div>`;
  if (products.length === 0) { html += `<div class="prod-empty">No products available yet.</div>`; }
  else { html += `<div class="prod-grid">${products.map(buildProductCard).join('')}</div>`; }
  html += `</section></div>` + buildFooter();
  return html;
}

function buildPaymentPage(params, env, loggedInUser) {
  const name = params.get('name') || '';
  const price = Number(params.get('price') || 0);
  const oldPrice = Number(params.get('oldPrice') || 0);
  const image = params.get('image') || '';
  const category = params.get('category') || '';
  const slug = params.get('slug') || '';
  const duration = params.get('duration') || '';

  let html = buildHeader(slug ? `/product/${encodeURIComponent(slug)}` : '/', "Checkout");

  if (!name) {
    html += `<div class="container"><section class="section"><div class="checkout-wrap"><div class="checkout-card"><div class="checkout-empty"><i class="fa-solid fa-cart-shopping"></i>No product selected. Please go back and choose a product to order.</div></div><div style="text-align:center;"><a href="/all-products" class="btn-home"><i class="fa-solid fa-grid-2"></i> Browse Products</a></div></div></section></div>`;
    html += buildFooter();
    return html;
  }

  const methods = PAYMENT_METHODS(env);
  const waAdmin1 = (env && env.WHATSAPP_ADMIN1) ? env.WHATSAPP_ADMIN1 : DEFAULT_WHATSAPP_ADMIN1;
  const waAdmin2 = (env && env.WHATSAPP_ADMIN2) ? env.WHATSAPP_ADMIN2 : DEFAULT_WHATSAPP_ADMIN2;

  const thumb = image
    ? `<img src="${escapeHtml(image)}" alt="${escapeHtml(name)}" onerror="this.parentElement.innerHTML='<i class=\\'fa-solid fa-image\\'></i>'">`
    : `<i class="fa-solid fa-image"></i>`;

  // Payment method dropdown — a single <select> listing all methods (JazzCash,
  // EasyPaisa, Meezan Bank...), so the user picks one from the list instead of cards.
  const methodOptionsHtml = methods.map((m, i) =>
    `<option value="${m.id}"${i === 0 ? ' selected' : ''}>${escapeHtml(m.label)}</option>`
  ).join('');

  const accountBoxesHtml = methods.map(m => `<div class="pay-account-box" data-account-for="${m.id}">
      <div class="pay-account-row"><span class="lbl">Account Title</span><span class="val">${escapeHtml(m.accountTitle)}</span></div>
      <div class="pay-account-row"><span class="lbl">${escapeHtml(m.accountLabel)}</span><span class="val">${escapeHtml(m.accountNumber)}</span><button type="button" class="copy-btn" data-copy="${escapeHtml(m.accountNumber)}">Copy</button></div>
    </div>`).join('');

  html += `<div class="container"><section class="section">
    <div class="checkout-wrap">
      <div class="breadcrumb"><a href="/">Home</a><i class="fa-solid fa-chevron-right"></i><span>Checkout</span></div>
      <div class="page-head" style="margin-bottom:20px;"><div><h1 style="font-size:23px;">Confirm Your Order</h1></div></div>

      <div class="checkout-card">
        <div class="checkout-prod">
          <div class="thumb">${thumb}</div>
          <div class="info">
            <div class="cat">${escapeHtml(category)}</div>
            <h3>${escapeHtml(name)}</h3>
            <div class="price"><span class="now">${money(price)}</span>${oldPrice ? `<span class="was">${money(oldPrice)}</span>` : ''}</div>
          </div>
        </div>
        <div class="checkout-rows">
          ${duration ? `<div class="checkout-row"><span class="lbl">Subscription Duration</span><span>${escapeHtml(duration)}</span></div>` : ''}
          <div class="checkout-row"><span class="lbl">Product Price</span><span>${money(price)}</span></div>
          <div class="checkout-row"><span class="lbl">Delivery</span><span>Digital — Instant</span></div>
          <div class="checkout-row total"><span>Total</span><span>${money(price)}</span></div>
        </div>
      </div>

      <div id="orderSuccessBox" style="display:none;"></div>

      ${!loggedInUser ? `
      <div id="authGateWrap">
        <div class="pay-section-title"><i class="fa-solid fa-lock"></i> Log In or Sign Up to Continue</div>
        <div class="checkout-note" style="margin-bottom:16px;"><i class="fa-solid fa-circle-info"></i><span>You need an account so we can confirm your order status. It only takes a moment.</span></div>

        <div class="auth-tabs">
          <button type="button" class="auth-tab-btn active" data-tab="login">Log In</button>
          <button type="button" class="auth-tab-btn" data-tab="signup">Sign Up</button>
        </div>

        <form id="loginForm" class="order-form show auth-tab-panel" data-panel="login" novalidate>
          <div class="form-group"><label for="loginEmail">Email Address</label><input type="email" id="loginEmail" maxlength="100" required></div>
          <div class="form-group"><label for="loginPassword">Password</label><input type="password" id="loginPassword" maxlength="200" required></div>
          <button type="submit" id="loginBtn" class="btn-submit-order"><i class="fa-solid fa-right-to-bracket"></i> Log In</button>
          <div id="loginMsg" class="form-msg"></div>
        </form>

        <form id="signupForm" class="order-form auth-tab-panel" data-panel="signup" style="display:none;" novalidate>
          <div class="form-group"><label for="signupName">Full Name</label><input type="text" id="signupName" maxlength="100" required></div>
          <div class="form-group"><label for="signupEmail">Email Address</label><input type="email" id="signupEmail" maxlength="100" required></div>
          <div class="form-group"><label for="signupPassword">Password</label><input type="password" id="signupPassword" maxlength="200" minlength="6" required></div>
          <button type="submit" id="signupBtn" class="btn-submit-order"><i class="fa-solid fa-user-plus"></i> Sign Up</button>
          <div id="signupMsg" class="form-msg"></div>
        </form>
      </div>
      ` : `
      <div id="orderFormWrap">
        <div class="pay-section-title"><i class="fa-solid fa-credit-card"></i> Choose Payment Method</div>
        <div class="pay-methods" id="payMethods">
          <select id="payMethodSelect" class="pay-method-select">${methodOptionsHtml}</select>
        </div>

        ${accountBoxesHtml}

        <form id="orderForm" class="order-form" novalidate>
          <div class="pay-divider"></div>
          <div class="form-row-2">
            <div class="form-group"><label for="custName">Full Name</label><input type="text" id="custName" maxlength="80" required></div>
            <div class="form-group"><label for="custPhone">Phone Number</label><input type="tel" id="custPhone" maxlength="20" required></div>
          </div>
          <div class="form-group"><label for="custEmail">Email Address</label><input type="email" id="custEmail" maxlength="100" value="${escapeHtml(loggedInUser.email || '')}" readonly></div>
          <div class="form-group"><label for="senderAccount" id="senderLabel">Sender Account Number</label><input type="text" id="senderAccount" maxlength="60" required></div>
          <div class="form-group"><label for="transactionId">Transaction ID</label><input type="text" id="transactionId" maxlength="80" required></div>
          <div class="form-group">
            <label>Payment Screenshot</label>
            <div class="upload-box" id="uploadBox">
              <i class="fa-solid fa-cloud-arrow-up"></i>
              <span id="uploadHint">Tap to upload screenshot (max 5MB)</span>
              <input type="file" id="screenshotInput" accept="image/*">
            </div>
            <div class="upload-preview" id="uploadPreview"><img id="uploadPreviewImg" src="" alt="Payment screenshot preview"></div>
          </div>
          <button type="submit" id="submitOrderBtn" class="btn-submit-order"><i class="fa-solid fa-paper-plane"></i> Submit Order</button>
          <div id="orderFormMsg" class="form-msg"></div>
        </form>
      </div>
      `}

      <div class="pay-divider" style="margin-top:22px;"></div>
      <div class="checkout-note">
        <i class="fa-brands fa-whatsapp"></i>
        <span>Prefer WhatsApp instead? You can send your order details directly to us there too.</span>
      </div>
      <div class="wa-dropdown-wrap">
        <div class="wa-dropdown-menu" id="waDropdownMenu">
          <button type="button" class="wa-dropdown-item" data-admin="1"><i class="fa-brands fa-whatsapp"></i> Admin 1</button>
          <button type="button" class="wa-dropdown-item" data-admin="2"><i class="fa-brands fa-whatsapp"></i> Admin 2</button>
        </div>
        <button type="button" id="waDropdownBtn" class="btn-whatsapp btn-whatsapp-sm" style="background:var(--surface); color:var(--whatsapp); border:1.5px solid var(--whatsapp); box-shadow:none;">
          <i class="fa-brands fa-whatsapp"></i> Message Us on WhatsApp <i class="fa-solid fa-chevron-down" style="font-size:11px;"></i>
        </button>
      </div>
    </div>
  </section></div>
  <script>
  (function(){
    // ===== Login / Signup tabs (only present when the visitor is not logged in) =====
    var tabBtns = document.querySelectorAll('.auth-tab-btn');
    tabBtns.forEach(function(btn){
      btn.addEventListener('click', function(){
        var tab = btn.getAttribute('data-tab');
        tabBtns.forEach(function(b){ b.classList.toggle('active', b === btn); });
        document.querySelectorAll('.auth-tab-panel').forEach(function(p){
          p.style.display = (p.getAttribute('data-panel') === tab) ? 'flex' : 'none';
        });
      });
    });

    var loginForm = document.getElementById('loginForm');
    if (loginForm) {
      loginForm.addEventListener('submit', function(e){
        e.preventDefault();
        var msgEl = document.getElementById('loginMsg');
        var btn = document.getElementById('loginBtn');
        var email = document.getElementById('loginEmail').value.trim();
        var password = document.getElementById('loginPassword').value;
        msgEl.textContent = ''; msgEl.className = 'form-msg';
        if (!email || !password) { msgEl.textContent = 'Please enter your email and password.'; msgEl.className = 'form-msg error'; return; }

        btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Logging in...';
        fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password }) })
          .then(function(r){ return r.json(); })
          .then(function(res){
            if (res && res.success) {
              window.location.reload();
            } else {
              btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Log In';
              msgEl.textContent = (res && res.error) || 'Login failed. Please try again.';
              msgEl.className = 'form-msg error';
            }
          })
          .catch(function(){
            btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Log In';
            msgEl.textContent = 'Network error. Please try again.';
            msgEl.className = 'form-msg error';
          });
      });
    }

    var signupForm = document.getElementById('signupForm');
    if (signupForm) {
      signupForm.addEventListener('submit', function(e){
        e.preventDefault();
        var msgEl = document.getElementById('signupMsg');
        var btn = document.getElementById('signupBtn');
        var name = document.getElementById('signupName').value.trim();
        var email = document.getElementById('signupEmail').value.trim();
        var password = document.getElementById('signupPassword').value;
        msgEl.textContent = ''; msgEl.className = 'form-msg';
        if (!name || !email || !password) { msgEl.textContent = 'Please fill in all fields.'; msgEl.className = 'form-msg error'; return; }
        if (password.length < 6) { msgEl.textContent = 'Password must be at least 6 characters.'; msgEl.className = 'form-msg error'; return; }

        btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Signing up...';
        fetch('/api/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name, email: email, password: password }) })
          .then(function(r){ return r.json(); })
          .then(function(res){
            if (res && res.success) {
              window.location.reload();
            } else {
              btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Sign Up';
              msgEl.textContent = (res && res.error) || 'Signup failed. Please try again.';
              msgEl.className = 'form-msg error';
            }
          })
          .catch(function(){
            btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Sign Up';
            msgEl.textContent = 'Network error. Please try again.';
            msgEl.className = 'form-msg error';
          });
      });
    }

    // ===== WhatsApp dropdown (Admin 1 / Admin 2) =====
    var waBtn = document.getElementById('waDropdownBtn');
    var waMenu = document.getElementById('waDropdownMenu');
    if (waBtn && waMenu) {
      waBtn.addEventListener('click', function(e){
        e.stopPropagation();
        waMenu.classList.toggle('show');
      });
      document.addEventListener('click', function(){ waMenu.classList.remove('show'); });

      var waFieldVal = function(id){ var el = document.getElementById(id); return el ? el.value.trim() : ''; };
      var waAdminNumbers = { '1': ${JSON.stringify(waAdmin1)}, '2': ${JSON.stringify(waAdmin2)} };

      var buildWaMessage = function(){
        var lines = ['Hi SJsubs! I want to order:', '', '*' + ${JSON.stringify(name)} + '*'];
        if (${JSON.stringify(category)}) lines.push('Category: ' + ${JSON.stringify(category)});
        if (${JSON.stringify(duration)}) lines.push('Duration: ' + ${JSON.stringify(duration)});
        lines.push('Price: ' + ${JSON.stringify(money(price))});

        var methodSelectEl = document.getElementById('payMethodSelect');
        var methodLabel = methodSelectEl ? methodSelectEl.options[methodSelectEl.selectedIndex].text : '';
        var custNameV = waFieldVal('custName');
        var custPhoneV = waFieldVal('custPhone');
        var custEmailV = waFieldVal('custEmail');
        var senderAccountV = waFieldVal('senderAccount');
        var transactionIdV = waFieldVal('transactionId');

        if (custNameV || custPhoneV || custEmailV || senderAccountV || transactionIdV) {
          lines.push('', '--- My Order Details ---');
          if (custNameV) lines.push('Name: ' + custNameV);
          if (custPhoneV) lines.push('Phone: ' + custPhoneV);
          if (custEmailV) lines.push('Email: ' + custEmailV);
          if (methodLabel) lines.push('Payment Method: ' + methodLabel);
          if (senderAccountV) lines.push('Sender Account: ' + senderAccountV);
          if (transactionIdV) lines.push('Transaction ID: ' + transactionIdV);
          lines.push('', '(Payment screenshot attached on the website — please check my order.)');
        } else {
          lines.push('', 'Please confirm availability and payment details.');
        }
        return lines.join('\\n');
      };

      document.querySelectorAll('.wa-dropdown-item').forEach(function(item){
        item.addEventListener('click', function(){
          var number = waAdminNumbers[item.getAttribute('data-admin')];
          window.open('https://wa.me/' + number + '?text=' + encodeURIComponent(buildWaMessage()), '_blank', 'noopener');
          waMenu.classList.remove('show');
        });
      });
    }

    var methodMeta = ${JSON.stringify(methods.map(m => ({ id: m.id, senderLabel: m.senderLabel })))};
    var selectedMethod = null;
    var methodSelect = document.getElementById('payMethodSelect');
    var accountBoxes = document.querySelectorAll('.pay-account-box');
    var orderForm = document.getElementById('orderForm');
    var senderLabelEl = document.getElementById('senderLabel');

    function applySelectedMethod(){
      selectedMethod = methodSelect ? methodSelect.value : null;
      accountBoxes.forEach(function(b){ b.classList.toggle('show', b.getAttribute('data-account-for') === selectedMethod); });
      if (orderForm) orderForm.classList.add('show');
      var meta = methodMeta.find(function(x){ return x.id === selectedMethod; });
      if (senderLabelEl && meta) senderLabelEl.textContent = meta.senderLabel;
    }

    if (methodSelect) {
      methodSelect.addEventListener('change', applySelectedMethod);
      applySelectedMethod(); // pre-select the first option (JazzCash) on page load
    }

    document.querySelectorAll('.copy-btn').forEach(function(btn){
      btn.addEventListener('click', function(e){
        e.stopPropagation();
        var val = btn.getAttribute('data-copy');
        if (navigator.clipboard) {
          navigator.clipboard.writeText(val).then(function(){
            var orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function(){ btn.textContent = orig; }, 1500);
          });
        }
      });
    });

    var uploadBox = document.getElementById('uploadBox');
    var screenshotInput = document.getElementById('screenshotInput');
    var uploadHint = document.getElementById('uploadHint');
    var uploadPreview = document.getElementById('uploadPreview');
    var uploadPreviewImg = document.getElementById('uploadPreviewImg');
    var selectedFile = null;

    if (screenshotInput) {
      screenshotInput.addEventListener('change', function(){
        var file = screenshotInput.files[0];
        if (!file) return;
        if (file.size > 5 * 1024 * 1024) {
          alert('Image must be under 5MB.');
          screenshotInput.value = '';
          return;
        }
        selectedFile = file;
        uploadBox.classList.add('has-file');
        uploadHint.textContent = file.name;
        var reader = new FileReader();
        reader.onload = function(e){
          uploadPreviewImg.src = e.target.result;
          uploadPreview.style.display = 'block';
        };
        reader.readAsDataURL(file);
      });
    }

    var submitBtn = document.getElementById('submitOrderBtn');
    var msgEl = document.getElementById('orderFormMsg');

    if (orderForm) {
      orderForm.addEventListener('submit', function(e){
        e.preventDefault();
        msgEl.textContent = '';
        msgEl.className = 'form-msg';

        if (!selectedMethod) { msgEl.textContent = 'Please choose a payment method.'; msgEl.className = 'form-msg error'; return; }
        var custName = document.getElementById('custName').value.trim();
        var custPhone = document.getElementById('custPhone').value.trim();
        var custEmail = document.getElementById('custEmail').value.trim();
        var senderAccount = document.getElementById('senderAccount').value.trim();
        var transactionId = document.getElementById('transactionId').value.trim();

        if (!custName || !custPhone || !custEmail || !senderAccount || !transactionId) {
          msgEl.textContent = 'Please fill in all fields.'; msgEl.className = 'form-msg error'; return;
        }
        var custEmailField = document.getElementById('custEmail');
        var emailIsLocked = custEmailField && custEmailField.hasAttribute('readonly');
        if (!emailIsLocked && !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(custEmail)) {
          msgEl.textContent = 'Please enter a valid email address.'; msgEl.className = 'form-msg error'; return;
        }
        if (!selectedFile) {
          msgEl.textContent = 'Please upload your payment screenshot.'; msgEl.className = 'form-msg error'; return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';

        var fd = new FormData();
        fd.append('productName', ${JSON.stringify(name)});
        fd.append('productSlug', ${JSON.stringify(slug)});
        fd.append('category', ${JSON.stringify(category)});
        fd.append('duration', ${JSON.stringify(duration)});
        fd.append('price', ${JSON.stringify(String(price))});
        fd.append('paymentMethod', selectedMethod);
        fd.append('customerName', custName);
        fd.append('customerPhone', custPhone);
        fd.append('customerEmail', custEmail);
        fd.append('senderAccount', senderAccount);
        fd.append('transactionId', transactionId);
        fd.append('screenshot', selectedFile);

        fetch('/api/submit-order', { method: 'POST', body: fd })
          .then(function(r){ return r.json(); })
          .then(function(res){
            if (res && res.success) {
              console.log('EmailJS notification result:', res.emailDebug);
              console.log('Welcome email result:', res.welcomeEmailDebug);
              document.getElementById('orderFormWrap').style.display = 'none';
              var box = document.getElementById('orderSuccessBox');
              box.style.display = 'block';
              box.innerHTML = '<div class="checkout-card"><div class="order-success"><i class="fa-solid fa-circle-check"></i><h2>Order Submitted!</h2><p>We have received your order details. Our team will verify your payment and activate your subscription shortly.</p><a href="/all-products" class="btn-home"><i class="fa-solid fa-grid-2"></i> Continue Shopping</a></div></div>';
            } else {
              submitBtn.disabled = false;
              submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Order';
              msgEl.textContent = (res && res.error) || 'Something went wrong. Please try again.';
              msgEl.className = 'form-msg error';
            }
          })
          .catch(function(){
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Order';
            msgEl.textContent = 'Network error. Please try again.';
            msgEl.className = 'form-msg error';
          });
      });
    }
  })();
  </script>`;
  html += buildFooter();
  return html;
}

// ========== FIRESTORE REST API ==========

async function queryFirestore(env, structuredQuery) {
  const API_KEY = env.FIRESTORE_API_KEY;
  const projectId = "smmm-eae44";
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/default/documents:runQuery`;

  if (!API_KEY) {
    console.error("Firestore error: FIRESTORE_API_KEY is missing/empty in env");
    return [];
  }

  const res = await fetch(`${url}?key=${API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ structuredQuery })
  });

  if (!res.ok) {
    const bodyText = await res.text().catch(() => "");
    console.error(`Firestore error: ${res.status} — ${bodyText}`);
    return [];
  }

  const data = await res.json();
  const results = [];

  if (data && Array.isArray(data)) {
    data.forEach(function(item) {
      if (item.document) {
        const doc = item.document;
        const id = doc.name.split('/').pop();
        const fields = doc.fields || {};
        const obj = { id: id };
        Object.keys(fields).forEach(function(key) {
          const field = fields[key];
          if (field.stringValue !== undefined) obj[key] = field.stringValue;
          else if (field.integerValue !== undefined) obj[key] = parseInt(field.integerValue);
          else if (field.doubleValue !== undefined) obj[key] = field.doubleValue;
          else if (field.booleanValue !== undefined) obj[key] = field.booleanValue;
          else if (field.nullValue !== undefined) obj[key] = null;
          else if (field.timestampValue) obj[key] = new Date(field.timestampValue).getTime();
        });
        results.push(obj);
      }
    });
  }
  return results;
}

async function getProductsByCategory(env, categoryName) {
  return queryFirestore(env, {
    from: [{ collectionId: "products" }],
    where: { fieldFilter: { field: { fieldPath: "category" }, op: "EQUAL", value: { stringValue: decodeURIComponent(categoryName) } } },
    orderBy: [{ field: { fieldPath: "createdAt" }, direction: "DESCENDING" }]
  });
}

async function getProductBySlug(env, slug) {
  const results = await queryFirestore(env, {
    from: [{ collectionId: "products" }],
    where: { fieldFilter: { field: { fieldPath: "slug" }, op: "EQUAL", value: { stringValue: slug } } },
    limit: 1
  });
  return results.length > 0 ? results[0] : null;
}

async function getAllProducts(env) {
  return queryFirestore(env, {
    from: [{ collectionId: "products" }],
    orderBy: [{ field: { fieldPath: "createdAt" }, direction: "DESCENDING" }]
  });
}

async function getRelatedProducts(env, category, excludeSlug) {
  if (!category) return [];
  const results = await queryFirestore(env, {
    from: [{ collectionId: "products" }],
    where: { fieldFilter: { field: { fieldPath: "category" }, op: "EQUAL", value: { stringValue: category } } },
    orderBy: [{ field: { fieldPath: "createdAt" }, direction: "DESCENDING" }],
    limit: 9
  });
  return results.filter(function(p) { return p.slug !== excludeSlug; }).slice(0, 8);
}

async function sendOrderNotificationEmail(env, order) {
  const serviceId = (env && env.EMAILJS_SERVICE_ID) || DEFAULT_EMAILJS_SERVICE_ID;
  const templateId = (env && env.EMAILJS_TEMPLATE_ID) || DEFAULT_EMAILJS_TEMPLATE_ID;
  const publicKey = (env && env.EMAILJS_PUBLIC_KEY) || DEFAULT_EMAILJS_PUBLIC_KEY;
  const privateKey = (env && env.EMAILJS_PRIVATE_KEY) || DEFAULT_EMAILJS_PRIVATE_KEY;
  const notifyEmail = (env && env.NOTIFY_EMAIL) || DEFAULT_NOTIFY_EMAIL;

  const res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      service_id: serviceId,
      template_id: templateId,
      user_id: publicKey,
      accessToken: privateKey,
      template_params: {
        to_email: notifyEmail,
        order_time: new Date().toLocaleString("en-PK", { timeZone: "Asia/Karachi" }),
        product_name: order.productName,
        category: order.category,
        duration: order.duration,
        price: money(order.price),
        customer_name: order.customerName,
        customer_phone: order.customerPhone,
        customer_email: order.customerEmail,
        payment_method: order.paymentMethod,
        sender_account: order.senderAccount,
        transaction_id: order.transactionId,
        screenshot_url: order.screenshotUrl
      }
    })
  });
  if (!res.ok) {
    const errText = await res.text().catch(function(){ return ""; });
    console.log("EmailJS send failed:", res.status, errText);
    return { ok: false, status: res.status, error: errText };
  }
  return { ok: true };
}

// Sends the customer-facing "welcome / thank you" email by calling the second,
// dedicated email-sending worker (bound as env.EMAIL_WORKER — see wrangler.toml).
// That worker doesn't exist yet; once it's built and deployed, it just needs to
// handle a POST to /send-welcome with this JSON body and send the email itself
// (e.g. via its own EmailJS call) using the professional welcome-email template.
async function sendWelcomeEmail(env, data) {
  if (!env.EMAIL_WORKER) {
    return { ok: false, error: "EMAIL_WORKER service binding not connected yet (second worker not deployed)." };
  }
  try {
    const res = await env.EMAIL_WORKER.fetch("https://email-worker.internal/send-welcome", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        customer_name: data.customerName,
        customer_email: data.customerEmail,
        product_name: data.productName,
        order_time: new Date().toLocaleString("en-PK", { timeZone: "Asia/Karachi" })
      })
    });
    if (!res.ok) {
      const errText = await res.text().catch(function(){ return ""; });
      console.log("Welcome email failed:", res.status, errText);
      return { ok: false, status: res.status, error: errText };
    }
    return { ok: true };
  } catch (err) {
    console.log("Welcome email error:", err);
    return { ok: false, error: String(err) };
  }
}

// ========== FIRESTORE WRITE HELPERS (for reviews) ==========

function toFirestoreFields(fields) {
  const out = {};
  Object.keys(fields).forEach(function(key) {
    const val = fields[key];
    if (val instanceof Date) out[key] = { timestampValue: val.toISOString() };
    else if (typeof val === "string") out[key] = { stringValue: val };
    else if (typeof val === "number") out[key] = Number.isInteger(val) ? { integerValue: val } : { doubleValue: val };
    else if (typeof val === "boolean") out[key] = { booleanValue: val };
  });
  return out;
}

async function addFirestoreDocument(env, collectionId, fields) {
  const API_KEY = env.FIRESTORE_API_KEY;
  const projectId = "smmm-eae44";
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/default/documents/${collectionId}?key=${API_KEY}`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fields: toFirestoreFields(fields) })
  });

  if (!res.ok) { console.error(`Firestore write error: ${res.status}`); return null; }
  return await res.json();
}

async function updateFirestoreDocument(env, collectionId, docId, fields) {
  const API_KEY = env.FIRESTORE_API_KEY;
  const projectId = "smmm-eae44";
  const fieldPaths = Object.keys(fields);
  const maskParams = fieldPaths.map(function(f) { return `updateMask.fieldPaths=${encodeURIComponent(f)}`; }).join("&");
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/default/documents/${collectionId}/${docId}?key=${API_KEY}&${maskParams}`;

  const res = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fields: toFirestoreFields(fields) })
  });

  if (!res.ok) { console.error(`Firestore update error: ${res.status}`); return null; }
  return await res.json();
}

async function getReviewsBySlug(env, slug) {
  return queryFirestore(env, {
    from: [{ collectionId: "reviews" }],
    where: { fieldFilter: { field: { fieldPath: "productSlug" }, op: "EQUAL", value: { stringValue: slug } } },
    orderBy: [{ field: { fieldPath: "createdAt" }, direction: "DESCENDING" }]
  });
}

// ========== KV HELPERS ==========

async function getFromKV(env, key) {
  try { return await env.SJSUBS_KV.get(key); } catch (e) { return null; }
}

async function setToKV(env, key, value, ttl) {
  try { await env.SJSUBS_KV.put(key, value, { expirationTtl: ttl || KV_CACHE_TTL }); } catch (e) {}
}

// ============================================
// 🚀 MAIN FETCH HANDLER — ALL ROUTES
// ============================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const siteUrl = env.SITE_URL || env.PUBLIC_BASE_URL || DEFAULT_SITE_URL;

    // ==========================================
    // 📸 ROUTE: R2 IMAGE UPLOAD (POST only)
    // ==========================================
    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    if (method === "POST") {
      // ==========================================
      // 👤 ROUTE: SIGN UP (creates a Firestore "users" doc, logs the user in)
      // ==========================================
      if (path === "/api/signup") {
        try {
          const body = await request.json();
          const name = (body.name || "").toString().trim().slice(0, 100);
          const email = (body.email || "").toString().trim().toLowerCase().slice(0, 100);
          const password = (body.password || "").toString();

          if (!name || !email || !password) {
            return json({ error: "Name, email and password are required." }, 400);
          }
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return json({ error: "Please enter a valid email address." }, 400);
          }
          if (password.length < 6) {
            return json({ error: "Password must be at least 6 characters." }, 400);
          }

          const existing = await getUserByEmail(env, email);
          if (existing) {
            return json({ error: "An account with this email already exists. Please log in instead." }, 409);
          }

          const { hash, salt } = await hashPassword(password);
          const created = await addFirestoreDocument(env, "users", {
            name, email, passwordHash: hash, passwordSalt: salt, createdAt: new Date()
          });
          if (!created || !created.name) {
            return json({ error: "Could not create account. Please try again." }, 500);
          }
          const userId = created.name.split("/").pop();

          const token = await createSessionToken(env, { id: userId, name, email });
          return new Response(JSON.stringify({ success: true, name, email }), {
            status: 200,
            headers: { "Content-Type": "application/json", "Set-Cookie": sessionCookieHeader(token), ...corsHeaders() }
          });
        } catch (err) {
          return json({ error: "Signup failed", detail: String(err) }, 500);
        }
      }

      // ==========================================
      // 🔑 ROUTE: LOG IN (verifies against Firestore "users" doc)
      // ==========================================
      if (path === "/api/login") {
        try {
          const body = await request.json();
          const email = (body.email || "").toString().trim().toLowerCase().slice(0, 100);
          const password = (body.password || "").toString();

          if (!email || !password) {
            return json({ error: "Email and password are required." }, 400);
          }

          const user = await getUserByEmail(env, email);
          if (!user) {
            return json({ error: "No account found with this email." }, 401);
          }
          const { hash } = await hashPassword(password, user.passwordSalt);
          if (hash !== user.passwordHash) {
            return json({ error: "Incorrect password." }, 401);
          }

          const token = await createSessionToken(env, { id: user.id, name: user.name, email: user.email });
          return new Response(JSON.stringify({ success: true, name: user.name, email: user.email }), {
            status: 200,
            headers: { "Content-Type": "application/json", "Set-Cookie": sessionCookieHeader(token), ...corsHeaders() }
          });
        } catch (err) {
          return json({ error: "Login failed", detail: String(err) }, 500);
        }
      }

      // ==========================================
      // ⭐ ROUTE: SUBMIT PRODUCT REVIEW (public, no admin key required)
      // ==========================================
      if (path === "/api/review") {
        try {
          const body = await request.json();
          const slug = (body.slug || "").toString().trim();
          const name = (body.name || "").toString().trim().slice(0, 60);
          const email = (body.email || "").toString().trim().slice(0, 120);
          const comment = (body.comment || "").toString().trim().slice(0, 500);
          let rating = parseInt(body.rating, 10);
          if (!Number.isFinite(rating) || rating < 1 || rating > 5) rating = 5;

          if (!slug || !name || !comment) {
            return json({ error: "Name and comment are required" }, 400);
          }
          if (!email || email.indexOf("@") === -1 || email.indexOf(".") === -1) {
            return json({ error: "A valid email is required" }, 400);
          }

          await addFirestoreDocument(env, "reviews", {
            productSlug: slug,
            name: name,
            email: email,
            rating: rating,
            comment: comment,
            createdAt: new Date()
          });

          // Update the product's aggregate rating + review count so cards/listings
          // show real numbers instead of a manually-set placeholder.
          const product = await getProductBySlug(env, slug);
          if (product) {
            const oldCount = Number(product.reviews) || 0;
            const oldRating = Number(product.rating) || 0;
            const newCount = oldCount + 1;
            const newRating = Math.round((((oldRating * oldCount) + rating) / newCount) * 10) / 10;
            await updateFirestoreDocument(env, "products", product.id, {
              reviews: newCount,
              rating: newRating
            });

            // Purge cached pages so the new rating shows up right away
            await env.SJSUBS_KV.delete("prod:" + slug).catch(() => {});
            if (product.category) await env.SJSUBS_KV.delete("cat:" + product.category).catch(() => {});
            await env.SJSUBS_KV.delete("page:all-products").catch(() => {});
          }

          return json({ success: true }, 200);
        } catch (err) {
          return json({ error: "Failed to submit review", detail: String(err) }, 500);
        }
      }

      // ==========================================
      // 🧾 ROUTE: SUBMIT ORDER (public, no admin key required)
      // Called from the payment page. Uploads the payment screenshot to R2 and
      // saves the full order (customer + payment + product details) to Firestore
      // so it shows up in the admin panel for verification.
      // ==========================================
      if (path === "/api/submit-order") {
        try {
          const loggedInUser = await getLoggedInUser(request, env);
          if (!loggedInUser) {
            return json({ error: "Please log in before placing an order." }, 401);
          }

          const formData = await request.formData();

          const productName = (formData.get("productName") || "").toString().trim().slice(0, 200);
          const productSlug = (formData.get("productSlug") || "").toString().trim().slice(0, 200);
          const category = (formData.get("category") || "").toString().trim().slice(0, 100);
          const duration = (formData.get("duration") || "").toString().trim().slice(0, 100);
          const price = Number(formData.get("price") || 0);
          const paymentMethod = (formData.get("paymentMethod") || "").toString().trim().slice(0, 40);
          const customerName = (formData.get("customerName") || "").toString().trim().slice(0, 100);
          const customerPhone = (formData.get("customerPhone") || "").toString().trim().slice(0, 30);
          const customerEmail = (formData.get("customerEmail") || "").toString().trim().slice(0, 100);
          const senderAccount = (formData.get("senderAccount") || "").toString().trim().slice(0, 100);
          const transactionId = (formData.get("transactionId") || "").toString().trim().slice(0, 100);
          const screenshot = formData.get("screenshot");

          if (!productName || !paymentMethod || !customerName || !customerPhone || !customerEmail || !senderAccount || !transactionId) {
            return json({ error: "Please fill in all required fields." }, 400);
          }
          if (!screenshot || typeof screenshot === "string") {
            return json({ error: "Please upload your payment screenshot." }, 400);
          }
          if (screenshot.size > MAX_IMAGE_SIZE) {
            return json({ error: "Screenshot is too large (max 5MB)." }, 400);
          }
          if (!screenshot.type.startsWith("image/")) {
            return json({ error: "Screenshot must be an image file." }, 400);
          }

          const ext = (screenshot.name.split(".").pop() || "jpg").toLowerCase();
          const key_name = `orders/${Date.now()}-${crypto.randomUUID()}.${ext}`;
          await env.BUCKET.put(key_name, screenshot.stream(), {
            httpMetadata: { contentType: screenshot.type },
          });
          const screenshotUrl = `${env.PUBLIC_BASE_URL}/${key_name}`;

          await addFirestoreDocument(env, "orders", {
            userUid: loggedInUser.uid,
            productName, productSlug, category, duration, price,
            paymentMethod, customerName, customerPhone, customerEmail, senderAccount, transactionId,
            screenshotUrl,
            status: "pending",
            createdAt: new Date()
          });

          const emailResult = await sendOrderNotificationEmail(env, {
            productName, category, duration, price,
            paymentMethod, customerName, customerPhone, customerEmail, senderAccount, transactionId,
            screenshotUrl
          }).catch(function(err){ return { ok: false, error: String(err) }; });

          const welcomeEmailResult = await sendWelcomeEmail(env, {
            customerName, customerEmail, productName
          }).catch(function(err){ return { ok: false, error: String(err) }; });

          return json({ success: true, emailDebug: emailResult, welcomeEmailDebug: welcomeEmailResult }, 200);
        } catch (err) {
          return json({ error: "Failed to submit order", detail: String(err) }, 500);
        }
      }

      // Auth check
      const key = request.headers.get("X-Admin-Key");
      if (!key || key !== env.ADMIN_UPLOAD_KEY) {
        return json({ error: "Unauthorized" }, 401);
      }

      // ==========================================
      // 🔥 ROUTE: ADMIN CACHE WARM (called by admin panel right after a product is saved)
      // Builds the product's HTML page NOW and stores it in KV, so the very first
      // visitor gets a warm cache instead of triggering the build on-demand.
      // Also purges the category + all-products KV pages so the new/updated
      // product shows up immediately in listings instead of waiting for TTL expiry.
      // ==========================================
      if (path === "/admin/cache-product") {
        try {
          const body = await request.json();
          const slug = body.slug;
          if (!slug) return json({ error: "Missing slug" }, 400);

          const product = await getProductBySlug(env, slug);
          if (!product) return json({ error: "Product not found in Firestore" }, 404);

          const related = await getRelatedProducts(env, product.category, product.slug);
          const html = buildProductDetailPage(product, siteUrl, related);
          await setToKV(env, "prod:" + slug, html, KV_CACHE_TTL);

          if (product.category) {
            await env.SJSUBS_KV.delete("cat:" + product.category).catch(() => {});
          }
          await env.SJSUBS_KV.delete("page:all-products").catch(() => {});

          return json({ success: true, slug, cached: true }, 200);
        } catch (err) {
          return json({ error: "Cache warm failed", detail: String(err) }, 500);
        }
      }

      // ==========================================
      // 🗑️ ROUTE: ADMIN CACHE CLEAR (called by admin panel right after a product is deleted)
      // ==========================================
      if (path === "/admin/uncache-product") {
        try {
          const body = await request.json();
          const { slug, category } = body;
          if (slug) await env.SJSUBS_KV.delete("prod:" + slug).catch(() => {});
          if (category) await env.SJSUBS_KV.delete("cat:" + category).catch(() => {});
          await env.SJSUBS_KV.delete("page:all-products").catch(() => {});
          return json({ success: true }, 200);
        } catch (err) {
          return json({ error: "Uncache failed", detail: String(err) }, 500);
        }
      }

      try {
        const formData = await request.formData();
        const file = formData.get("file");

        if (!file || typeof file === "string") {
          return json({ error: "No file provided" }, 400);
        }

        if (file.size > MAX_IMAGE_SIZE) {
          return json({ error: "File too large (max 5MB)" }, 400);
        }

        if (!file.type.startsWith("image/")) {
          return json({ error: "Only image files are allowed" }, 400);
        }

        const ext = (file.name.split(".").pop() || "jpg").toLowerCase();
        const key_name = `products/${Date.now()}-${crypto.randomUUID()}.${ext}`;

        await env.BUCKET.put(key_name, file.stream(), {
          httpMetadata: { contentType: file.type },
        });

        const publicUrl = `${env.PUBLIC_BASE_URL}/${key_name}`;
        return json({ url: publicUrl }, 200);
      } catch (err) {
        return json({ error: "Upload failed", detail: String(err) }, 500);
      }
    }

    // ==========================================
    // 📄 GET ROUTES — Pages
    // ==========================================

    try {
      // ===== /category/:name =====
      if (path.startsWith('/category/')) {
        const categoryName = decodeURIComponent(path.replace('/category/', ''));
        const kvKey = 'cat:' + categoryName;

        let html = await getFromKV(env, kvKey);
        if (html) {
          return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'X-Cache': 'HIT', 'Cache-Control': 'public, max-age=3600' } });
        }

        const products = await getProductsByCategory(env, categoryName);
        if (products.length === 0) {
          html = buildEmptyCategoryPage(categoryName);
          ctx.waitUntil(setToKV(env, kvKey, html, EMPTY_CACHE_TTL));
        } else {
          html = buildCategoryPage(categoryName, products);
          ctx.waitUntil(setToKV(env, kvKey, html, KV_CACHE_TTL));
        }

        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'X-Cache': 'MISS', 'Cache-Control': 'public, max-age=3600' } });
      }

      // ===== /product/:slug =====
      if (path.startsWith('/product/')) {
        const slug = path.replace('/product/', '');
        const kvKey = 'prod:' + slug;

        let html = await getFromKV(env, kvKey);
        if (html) {
          return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'X-Cache': 'HIT', 'Cache-Control': 'public, max-age=3600' } });
        }

        const product = await getProductBySlug(env, slug);
        if (!product) {
          html = buildNotFoundPage("Product Not Found", "This product may have been removed or doesn't exist.");
          return new Response(html, { status: 404, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        const related = await getRelatedProducts(env, product.category, product.slug);
        html = buildProductDetailPage(product, siteUrl, related);
        ctx.waitUntil(setToKV(env, kvKey, html, KV_CACHE_TTL));
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'X-Cache': 'MISS', 'Cache-Control': 'public, max-age=3600' } });
      }

      // ===== /api/reviews/:slug (public, returns real saved reviews as JSON) =====
      if (path.startsWith('/api/reviews/')) {
        const slug = decodeURIComponent(path.replace('/api/reviews/', ''));
        const reviews = await getReviewsBySlug(env, slug);
        return json({ reviews: reviews }, 200);
      }

      // ===== /all-products =====
      if (path === '/all-products') {
        const kvKey = 'page:all-products';

        let html = await getFromKV(env, kvKey);
        if (html) {
          return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'X-Cache': 'HIT', 'Cache-Control': 'public, max-age=3600' } });
        }

        const products = await getAllProducts(env);
        html = buildAllProductsPage(products);
        ctx.waitUntil(setToKV(env, kvKey, html, KV_CACHE_TTL));
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'X-Cache': 'MISS', 'Cache-Control': 'public, max-age=3600' } });
      }

      // ===== /payment.html (not cached — always fresh, driven by query params) =====
      if (path === '/payment.html') {
        const loggedInUser = await getLoggedInUser(request, env);
        const html = buildPaymentPage(url.searchParams, env, loggedInUser);
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' } });
      }

      // ===== 404 =====
      const notFoundHtml = buildNotFoundPage();
      return new Response(notFoundHtml, { status: 404, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

    } catch (err) {
      console.error('Worker fatal error:', err);
      const errorHtml = buildNotFoundPage("Something Went Wrong", "We're experiencing technical difficulties. Please try again.");
      return new Response(errorHtml, { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
  }
};

import { useState, useEffect, useRef, useCallback } from "react";

const BASE = "https://web-production-36a69.up.railway.app";

/* ══ ENCODING ════════════════════════════════════════════════════════════ */
const b64enc = buf => {
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
  let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
};
const b64dec = s => {
  const b = atob(s); const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u.buffer;
};
const bufToHex = buf => Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join(":");

/* ══ CRYPTO — AES-GCM wrapping (NOT AES-KW) ════════════════════════════ */
const genRSAKeyPair = () =>
  crypto.subtle.generateKey(
    { name:"RSA-OAEP", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256" },
    true, ["encrypt","decrypt"]
  );
const genSalt = () => crypto.getRandomValues(new Uint8Array(16));
const deriveWrapKey = async (password, salt) => {
  const raw = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:100_000, hash:"SHA-256" },
    raw, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]
  );
};
const wrapPrivKey = async (pk, wk) => {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, wk, pkcs8);
  const out = new Uint8Array(12 + enc.byteLength);
  out.set(iv,0); out.set(new Uint8Array(enc),12);
  return b64enc(out.buffer);
};
const unwrapPrivKey = async (b64, wk) => {
  const buf = new Uint8Array(b64dec(b64));
  const pkcs8 = await crypto.subtle.decrypt({ name:"AES-GCM", iv:buf.slice(0,12) }, wk, buf.slice(12));
  return crypto.subtle.importKey("pkcs8", pkcs8, { name:"RSA-OAEP", hash:"SHA-256" }, true, ["decrypt"]);
};
const exportPubKey = async k => b64enc(await crypto.subtle.exportKey("spki", k));
const importPubKey = b64 =>
  crypto.subtle.importKey("spki", b64dec(b64), { name:"RSA-OAEP", hash:"SHA-256" }, true, ["encrypt"]);
const encryptMsg = async (text, rPub, sPub) => {
  const aes = await crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, aes, new TextEncoder().encode(text));
  const raw = await crypto.subtle.exportKey("raw", aes);
  const [rk,sk] = await Promise.all([importPubKey(rPub), importPubKey(sPub)]);
  const [ek,eks] = await Promise.all([
    crypto.subtle.encrypt({ name:"RSA-OAEP" }, rk, raw),
    crypto.subtle.encrypt({ name:"RSA-OAEP" }, sk, raw),
  ]);
  return { ciphertext:b64enc(ct), iv:b64enc(iv), encryptedKey:b64enc(ek), encryptedKeyForSelf:b64enc(eks) };
};
const decryptMsg = async (payload, privKey, isSender) => {
  const ekB64 = isSender ? payload.encryptedKeyForSelf : payload.encryptedKey;
  const raw   = await crypto.subtle.decrypt({ name:"RSA-OAEP" }, privKey, b64dec(ekB64));
  const aes   = await crypto.subtle.importKey("raw", raw, { name:"AES-GCM" }, false, ["decrypt"]);
  return new TextDecoder().decode(
    await crypto.subtle.decrypt({ name:"AES-GCM", iv:b64dec(payload.iv) }, aes, b64dec(payload.ciphertext))
  );
};

/* ══ SERVER WAKE + API ═══════════════════════════════════════════════════ */
let _awake = false;
const wakeServer = () =>
  fetch(`${BASE}/health`, { signal: AbortSignal.timeout(15000) })
    .then(r => { if (r.ok) _awake = true; }).catch(() => {});

const api = async (method, path, body, token) => {
  const h = { "Content-Type":"application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  try {
    const res = await fetch(`${BASE}${path}`, {
      method, headers:h, body:body?JSON.stringify(body):undefined,
      signal: AbortSignal.timeout(20000),
    });
    const data = await res.json().catch(()=>({}));
    if (!res.ok) throw new Error(data.detail || `Error ${res.status}`);
    _awake = true; return data;
  } catch(err) {
    if (err.name==="AbortError"||err.name==="TimeoutError")
      throw new Error("Request timed out — server may be waking up. Try again.");
    if (err.message==="Failed to fetch")
      throw new Error("Cannot reach server. Check connection or try again shortly.");
    throw err;
  }
};

/* ══ SESSION ══════════════════════════════════════════════════════════════ */
const SS = {
  save:  (r,u) => { sessionStorage.setItem("sa_r",r); sessionStorage.setItem("sa_u",JSON.stringify(u)); },
  load:  ()   => { const r=sessionStorage.getItem("sa_r"),u=sessionStorage.getItem("sa_u"); return r&&u?{refresh:r,user:JSON.parse(u)}:null; },
  clear: ()   => { sessionStorage.removeItem("sa_r"); sessionStorage.removeItem("sa_u"); },
};
const LS = {
  get: (k,d=null) => { try { const v=localStorage.getItem(k); return v!==null?JSON.parse(v):d; } catch { return d; } },
  set: (k,v)      => { try { localStorage.setItem(k,JSON.stringify(v)); } catch {} },
};

/* ══ SOUND ════════════════════════════════════════════════════════════════ */
const playPing = () => {
  try {
    const ctx = new (window.AudioContext||window.webkitAudioContext)();
    const osc = ctx.createOscillator(); const g = ctx.createGain();
    osc.connect(g); g.connect(ctx.destination);
    osc.frequency.value = 880; osc.type = "sine";
    g.gain.setValueAtTime(0, ctx.currentTime);
    g.gain.linearRampToValueAtTime(0.15, ctx.currentTime+0.01);
    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime+0.3);
    osc.start(); osc.stop(ctx.currentTime+0.3);
  } catch {}
};

/* ══ HELPERS ══════════════════════════════════════════════════════════════ */
const fmtTime  = iso => new Date(iso).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
const fmtFull  = iso => new Date(iso).toLocaleString([],{weekday:"short",month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});
const fmtLabel = iso => {
  const d=new Date(iso),n=new Date();
  if (d.toDateString()===n.toDateString()) return fmtTime(iso);
  const y=new Date(n); y.setDate(n.getDate()-1);
  if (d.toDateString()===y.toDateString()) return "Yesterday";
  return d.toLocaleDateString([],{month:"short",day:"numeric"});
};
const fmtLastSeen = iso => {
  if (!iso) return "";
  const diff = Date.now()-new Date(iso).getTime();
  if (diff<60000)    return "last seen just now";
  if (diff<3600000)  return `last seen ${Math.floor(diff/60000)}m ago`;
  if (diff<86400000) return `last seen ${Math.floor(diff/3600000)}h ago`;
  return `last seen ${new Date(iso).toLocaleDateString([],{month:"short",day:"numeric"})}`;
};
const initials  = n => (n||"?").split(" ").slice(0,2).map(w=>w[0]).join("").toUpperCase();
const colorIdx  = n => [...(n||"")].reduce((a,c)=>a+c.charCodeAt(0),0)%8;
const TG_COLORS = ["#2CA5E0","#E84E74","#A260CE","#E67E22","#1BA0A0","#E05B36","#16A085","#8D5EB7"];
const EMOJI_LIST = ["👍","❤️","🔥","🎉","😂","😮","😢","🙏"];

/* ══ CSS ══════════════════════════════════════════════════════════════════ */
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@400;500;600&family=Roboto:wght@300;400;500&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body,#root{height:100%;-webkit-tap-highlight-color:transparent;overscroll-behavior:none;}

:root{
  --tg-bg:#17212B;
  --tg-sb:#232E3C;
  --tg-input:#182533;
  --tg-surf:#1C2733;
  --tg-surf2:#242F3D;
  --tg-bord:rgba(255,255,255,.06);
  --tg-accent:#2CA5E0;
  --tg-accent2:#1A8AC4;
  --tg-sent:#2B5278;
  --tg-sent-tail:#2B5278;
  --tg-recv:#182533;
  --tg-txt:#FFFFFF;
  --tg-txt2:#708EA7;
  --tg-txt3:#4A6478;
  --tg-green:#4DCD5E;
  --tg-red:#EC3942;
  --tg-divider:rgba(255,255,255,.08);
  --font:'Roboto',sans-serif;
  --safe-bottom:env(safe-area-inset-bottom,0px);
  --safe-top:env(safe-area-inset-top,0px);
}
[data-theme="light"]{
  --tg-bg:#FFFFFF;
  --tg-sb:#F4F4F5;
  --tg-input:#F0F0F0;
  --tg-surf:#FFFFFF;
  --tg-surf2:#F4F4F5;
  --tg-bord:rgba(0,0,0,.08);
  --tg-accent:#2CA5E0;
  --tg-accent2:#1A8AC4;
  --tg-sent:#EFFDDE;
  --tg-sent-tail:#CDEAB0;
  --tg-recv:#FFFFFF;
  --tg-txt:#000000;
  --tg-txt2:#8E8E93;
  --tg-txt3:#C7C7CC;
  --tg-green:#37C635;
  --tg-red:#FF3B30;
  --tg-divider:rgba(0,0,0,.08);
}

body{background:var(--tg-bg);color:var(--tg-txt);font-family:var(--font);transition:background .2s,color .2s;}

/* ── SHELL ── */
.tg-shell{display:flex;height:100svh;overflow:hidden;position:relative;}

/* ── LEFT PANEL ── */
.tg-left{
  width:360px;min-width:360px;display:flex;flex-direction:column;
  background:var(--tg-sb);border-right:1px solid var(--tg-divider);
  transition:transform .28s cubic-bezier(.4,0,.2,1),background .2s;
  position:relative;z-index:10;
}

/* ── TOP BAR ── */
.tg-topbar{
  height:56px;display:flex;align-items:center;gap:4px;padding:0 8px;
  background:var(--tg-sb);border-bottom:1px solid var(--tg-divider);
  flex-shrink:0;
}
.tg-topbar-title{font-size:20px;font-weight:700;color:var(--tg-txt);flex:1;padding-left:4px;}
.tg-search-bar{
  padding:6px 12px;background:var(--tg-sb);border-bottom:1px solid var(--tg-divider);
  flex-shrink:0;
}
.tg-search-inp{
  width:100%;padding:8px 12px 8px 36px;background:var(--tg-input);
  border:none;border-radius:20px;color:var(--tg-txt);font-family:var(--font);
  font-size:14px;outline:none;position:relative;
}
.tg-search-inp::placeholder{color:var(--tg-txt2);}
.tg-search-wrap{position:relative;}
.tg-search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--tg-txt2);pointer-events:none;}

/* ── CHAT LIST ── */
.tg-list{flex:1;overflow-y:auto;scrollbar-width:none;}
.tg-list::-webkit-scrollbar{display:none;}
.tg-list-item{
  display:flex;align-items:center;gap:10px;padding:8px 12px;
  cursor:pointer;transition:background .12s;position:relative;
}
.tg-list-item:hover{background:rgba(255,255,255,.04);}
[data-theme="light"] .tg-list-item:hover{background:rgba(0,0,0,.04);}
.tg-list-item.active{background:var(--tg-accent);}
.tg-list-item.active .tg-list-name{color:#fff;}
.tg-list-item.active .tg-list-time{color:rgba(255,255,255,.7);}
.tg-list-item.active .tg-list-preview{color:rgba(255,255,255,.8);}
.tg-list-item.active .tg-list-count{background:rgba(255,255,255,.3);color:#fff;}
.tg-list-info{flex:1;min-width:0;}
.tg-list-row1{display:flex;align-items:center;justify-content:space-between;margin-bottom:2px;}
.tg-list-name{font-size:15px;font-weight:500;color:var(--tg-txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.tg-list-time{font-size:13px;color:var(--tg-txt2);flex-shrink:0;margin-left:6px;}
.tg-list-row2{display:flex;align-items:center;justify-content:space-between;}
.tg-list-preview{font-size:14px;color:var(--tg-txt2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;}
.tg-list-count{background:var(--tg-accent);color:#fff;font-size:12px;font-weight:500;
  min-width:20px;height:20px;border-radius:10px;display:flex;align-items:center;
  justify-content:center;padding:0 5px;margin-left:6px;flex-shrink:0;}
.tg-list-mute{color:var(--tg-txt3);font-size:13px;margin-left:4px;}
.tg-divider-label{font-size:12px;color:var(--tg-txt2);padding:12px 16px 4px;font-weight:500;}

/* ── AVATAR ── */
.tg-av{position:relative;flex-shrink:0;}
.tg-av-img{border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-weight:500;color:#fff;font-size:15px;overflow:hidden;
  background-size:cover;background-position:center;}
.tg-av-online{position:absolute;bottom:0;right:0;width:11px;height:11px;
  border-radius:50%;background:var(--tg-green);border:2px solid var(--tg-sb);transition:background .2s;}
.tg-av-online.off{background:transparent;border-color:transparent;}
.tg-list-item.active .tg-av-online{border-color:var(--tg-accent);}

/* ── ME BAR ── */
.tg-me-bar{
  padding:10px 12px;border-top:1px solid var(--tg-divider);flex-shrink:0;
  display:flex;align-items:center;gap:10px;background:var(--tg-sb);
}
.tg-me-name{font-size:14px;font-weight:500;color:var(--tg-txt);}
.tg-me-status{font-size:12px;color:var(--tg-txt2);margin-top:1px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px;}

/* ── RIGHT / CHAT ── */
.tg-right{flex:1;display:flex;flex-direction:column;overflow:hidden;background:var(--tg-bg);position:relative;}

/* ── CHAT BG PATTERN ── */
.tg-chat-bg{
  position:absolute;inset:0;z-index:0;
  background-color:var(--tg-bg);
  background-image:radial-gradient(circle at 1px 1px, rgba(255,255,255,.03) 1px, transparent 0);
  background-size:20px 20px;
  pointer-events:none;
}
[data-theme="light"] .tg-chat-bg{
  background-image:radial-gradient(circle at 1px 1px, rgba(0,0,0,.04) 1px, transparent 0);
}

/* ── CHAT HEADER ── */
.tg-chat-head{
  height:56px;display:flex;align-items:center;gap:8px;padding:0 4px 0 0;
  background:var(--tg-sb);border-bottom:1px solid var(--tg-divider);
  flex-shrink:0;z-index:2;position:relative;
}
.tg-chat-head-info{flex:1;min-width:0;cursor:pointer;}
.tg-chat-head-name{font-size:15px;font-weight:600;color:var(--tg-txt);line-height:1.2;}
.tg-chat-head-sub{font-size:13px;color:var(--tg-accent);margin-top:1px;}

/* ── MESSAGES ── */
.tg-msgs{
  flex:1;overflow-y:auto;padding:8px 0 4px;display:flex;
  flex-direction:column;gap:2px;z-index:1;position:relative;
  scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent;
}
.tg-msgs::-webkit-scrollbar{width:4px;}
.tg-msgs::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px;}
[data-theme="light"] .tg-msgs::-webkit-scrollbar-thumb{background:rgba(0,0,0,.1);}

.tg-day-sep{
  display:flex;align-items:center;justify-content:center;margin:8px 0 4px;
}
.tg-day-sep span{
  background:rgba(30,60,90,.7);color:rgba(255,255,255,.8);font-size:12px;
  padding:4px 10px;border-radius:12px;backdrop-filter:blur(8px);
}
[data-theme="light"] .tg-day-sep span{
  background:rgba(200,220,240,.85);color:rgba(0,0,0,.6);
}

.tg-mrow{display:flex;padding:1px 8px;position:relative;}
.tg-mrow.me{justify-content:flex-end;}
.tg-mrow.you{justify-content:flex-start;}
.tg-mrow:hover .tg-react-btn{opacity:1;}

.tg-bubble-wrap{display:flex;flex-direction:column;max-width:75%;position:relative;}
.tg-mrow.me .tg-bubble-wrap{align-items:flex-end;}
.tg-mrow.you .tg-bubble-wrap{align-items:flex-start;}

/* Telegram bubble tails */
.tg-bubble{
  padding:7px 12px 6px;border-radius:18px;font-size:14.5px;
  line-height:1.45;word-break:break-word;position:relative;
  animation:fadeUp .12s ease-out;
}
.tg-mrow.me .tg-bubble{
  background:var(--tg-sent);color:#fff;
  border-bottom-right-radius:4px;
}
[data-theme="light"] .tg-mrow.me .tg-bubble{color:#000;}
.tg-mrow.you .tg-bubble{
  background:var(--tg-recv);color:var(--tg-txt);
  border-bottom-left-radius:4px;
  border:1px solid var(--tg-bord);
}

/* Tail SVGs */
.tg-tail{position:absolute;bottom:0;width:11px;height:20px;}
.tg-tail.me{right:-6px;fill:var(--tg-sent);}
.tg-tail.you{left:-6px;transform:scaleX(-1);fill:var(--tg-recv);}
[data-theme="light"] .tg-tail.me{fill:var(--tg-sent);}
[data-theme="light"] .tg-tail.you{fill:var(--tg-recv);}

/* bubble content */
.tg-bubble.deleted{opacity:.5;font-style:italic;}
.tg-bubble img{max-width:100%;border-radius:10px;margin-top:2px;display:block;}
.tg-file-chip{
  display:flex;align-items:center;gap:10px;padding:8px;
  background:rgba(255,255,255,.08);border-radius:10px;cursor:pointer;
  min-width:180px;transition:background .15s;
}
.tg-file-chip:hover{background:rgba(255,255,255,.14);}
[data-theme="light"] .tg-file-chip{background:rgba(0,0,0,.05);}
[data-theme="light"] .tg-file-chip:hover{background:rgba(0,0,0,.09);}
.tg-file-ico{width:40px;height:40px;border-radius:50%;background:rgba(44,165,224,.3);
  display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;}
.tg-file-info{}
.tg-file-name{font-size:13px;font-weight:500;color:var(--tg-txt);max-width:160px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.tg-file-size{font-size:12px;color:var(--tg-txt2);margin-top:2px;}

/* voice note */
.tg-voice{display:flex;align-items:center;gap:8px;padding:4px 0;min-width:180px;}
.tg-voice-btn{width:36px;height:36px;border-radius:50%;background:var(--tg-accent);
  border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;
  color:#fff;flex-shrink:0;transition:background .15s;}
.tg-voice-btn:hover{background:var(--tg-accent2);}
.tg-voice-bar{flex:1;height:24px;display:flex;align-items:center;gap:1.5px;}
.tg-voice-dot{width:3px;border-radius:2px;background:rgba(255,255,255,.5);transition:height .1s;}
.tg-voice-dur{font-size:12px;color:var(--tg-txt2);min-width:36px;text-align:right;}

/* reply quote */
.tg-reply{
  border-left:3px solid var(--tg-accent);padding:4px 8px;
  border-radius:0 6px 6px 0;margin-bottom:4px;
  background:rgba(44,165,224,.1);font-size:12px;
}
.tg-reply-name{color:var(--tg-accent);font-weight:500;margin-bottom:2px;}
.tg-reply-text{color:var(--tg-txt2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

/* meta */
.tg-meta{
  display:flex;align-items:center;gap:3px;font-size:11px;
  color:rgba(255,255,255,.5);float:right;margin-left:8px;
  margin-top:2px;position:relative;bottom:-2px;
}
.tg-mrow.you .tg-meta{color:var(--tg-txt2);}
[data-theme="light"] .tg-mrow.me .tg-meta{color:rgba(0,100,0,.6);}
.tg-tick{font-size:13px;}
.tg-tick.t1{opacity:.6;}
.tg-tick.t2{color:rgba(255,255,255,.8);}
.tg-tick.t3{color:#4DCD5E;}
[data-theme="light"] .tg-tick.t3{color:#37C635;}

/* reactions below bubble */
.tg-reactions{display:flex;flex-wrap:wrap;gap:3px;margin-top:2px;}
.tg-r-chip{
  font-size:13px;padding:3px 7px;border-radius:12px;cursor:pointer;
  background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.1);
  transition:all .15s;user-select:none;
}
[data-theme="light"] .tg-r-chip{background:rgba(0,0,0,.05);border-color:rgba(0,0,0,.08);}
.tg-r-chip:hover{background:rgba(44,165,224,.2);}
.tg-r-chip.mine{background:rgba(44,165,224,.25);border-color:rgba(44,165,224,.5);}

/* react btn on hover */
.tg-react-btn{
  opacity:0;position:absolute;top:-28px;background:var(--tg-sb);
  border:1px solid var(--tg-bord);border-radius:20px;padding:4px 8px;
  font-size:14px;cursor:pointer;transition:opacity .15s;z-index:5;
  box-shadow:0 2px 8px rgba(0,0,0,.3);
}
.tg-mrow.me .tg-react-btn{right:0;}
.tg-mrow.you .tg-react-btn{left:0;}

/* emoji picker */
.tg-emoji-picker{
  position:absolute;top:-52px;background:var(--tg-sb);border:1px solid var(--tg-bord);
  border-radius:24px;padding:6px 10px;display:flex;gap:4px;z-index:20;
  box-shadow:0 4px 20px rgba(0,0,0,.4);animation:fadeUp .12s ease-out;
}
.tg-mrow.me .tg-emoji-picker{right:0;}
.tg-mrow.you .tg-emoji-picker{left:0;}
.tg-ep-btn{font-size:20px;cursor:pointer;transition:transform .15s;padding:2px;}
.tg-ep-btn:hover{transform:scale(1.3);}

/* ── TYPING ── */
.tg-typing{
  display:flex;align-items:center;gap:6px;padding:8px 20px;
  font-size:13px;color:var(--tg-txt2);
}
.tg-typing-dots{display:flex;gap:3px;align-items:center;}
.tg-tdot{width:5px;height:5px;border-radius:50%;background:var(--tg-accent);
  animation:tgpulse 1.4s ease-in-out infinite;}
.tg-tdot:nth-child(2){animation-delay:.2s;}
.tg-tdot:nth-child(3){animation-delay:.4s;}

/* ── INPUT ── */
.tg-input-area{
  z-index:2;position:relative;background:var(--tg-sb);
  border-top:1px solid var(--tg-divider);
  padding-bottom:var(--safe-bottom);
}
.tg-reply-preview{
  display:flex;align-items:center;gap:8px;padding:8px 12px 0;
  border-bottom:1px solid var(--tg-divider);
}
.tg-reply-preview-body{
  flex:1;border-left:3px solid var(--tg-accent);padding:2px 8px;
  font-size:12px;min-width:0;
}
.tg-reply-preview-name{color:var(--tg-accent);font-weight:500;margin-bottom:2px;}
.tg-reply-preview-text{color:var(--tg-txt2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.tg-input-row{display:flex;align-items:flex-end;gap:6px;padding:8px 8px;}
.tg-textarea{
  flex:1;background:var(--tg-input);border:none;border-radius:22px;
  padding:10px 16px;color:var(--tg-txt);font-family:var(--font);font-size:15px;
  resize:none;outline:none;min-height:44px;max-height:140px;line-height:1.45;
  overflow-y:auto;transition:box-shadow .2s;
}
.tg-textarea:focus{box-shadow:0 0 0 2px rgba(44,165,224,.3);}
.tg-textarea::placeholder{color:var(--tg-txt2);}
.tg-send-btn{
  width:44px;height:44px;border-radius:50%;background:var(--tg-accent);border:none;
  cursor:pointer;display:flex;align-items:center;justify-content:center;
  color:#fff;flex-shrink:0;transition:background .15s,transform .1s;
}
.tg-send-btn:hover{background:var(--tg-accent2);}
.tg-send-btn:active{transform:scale(.92);}
.tg-send-btn:disabled{opacity:.4;cursor:not-allowed;}
.tg-send-btn.voice{background:rgba(255,255,255,.1);}
.tg-send-btn.voice:hover{background:rgba(255,255,255,.18);}
.tg-attach-btn{
  width:40px;height:40px;border-radius:50%;background:none;border:none;
  cursor:pointer;display:flex;align-items:center;justify-content:center;
  color:var(--tg-txt2);flex-shrink:0;transition:color .15s;
}
.tg-attach-btn:hover{color:var(--tg-accent);}

/* ── EMPTY STATE ── */
.tg-empty{
  flex:1;display:flex;flex-direction:column;align-items:center;
  justify-content:center;gap:12px;text-align:center;z-index:1;position:relative;
}
.tg-empty-icon{width:80px;height:80px;border-radius:50%;background:rgba(44,165,224,.15);
  display:flex;align-items:center;justify-content:center;font-size:36px;}
.tg-empty-title{font-size:20px;font-weight:600;color:var(--tg-txt);}
.tg-empty-sub{font-size:14px;color:var(--tg-txt2);max-width:260px;line-height:1.6;}
.tg-loading{flex:1;display:flex;align-items:center;justify-content:center;
  font-size:13px;color:var(--tg-txt2);z-index:1;position:relative;}

/* ── LOAD MORE ── */
.tg-load-more{
  align-self:center;padding:5px 16px;background:rgba(44,165,224,.15);
  border:1px solid rgba(44,165,224,.25);border-radius:16px;color:var(--tg-accent);
  font-size:13px;cursor:pointer;margin:6px 0;transition:all .15s;
}
.tg-load-more:hover{background:rgba(44,165,224,.25);}

/* ── MSG SEARCH BAR ── */
.tg-msg-search{
  display:flex;align-items:center;gap:8px;padding:6px 12px;
  background:var(--tg-sb);border-bottom:1px solid var(--tg-divider);
  z-index:2;position:relative;flex-shrink:0;
}
.tg-msg-search input{
  flex:1;padding:7px 12px;background:var(--tg-input);border:none;border-radius:18px;
  color:var(--tg-txt);font-family:var(--font);font-size:14px;outline:none;
}
.tg-msg-search input::placeholder{color:var(--tg-txt2);}

/* ── ICON BTN ── */
.ibtn{background:none;border:none;cursor:pointer;color:var(--tg-txt2);padding:8px;
  border-radius:50%;display:flex;align-items:center;justify-content:center;
  transition:color .15s,background .15s;flex-shrink:0;}
.ibtn:hover{color:var(--tg-txt);background:rgba(255,255,255,.06);}
[data-theme="light"] .ibtn:hover{background:rgba(0,0,0,.06);}

/* ── SETTINGS DRAWER ── */
.tg-scrim{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:300;
  display:flex;align-items:flex-end;justify-content:center;animation:fadeIn .2s;}
@media(min-width:641px){.tg-scrim{align-items:center;}}
.tg-sheet{
  background:var(--tg-sb);width:100%;max-width:480px;
  border-radius:20px 20px 0 0;padding:16px 16px 32px;max-height:92vh;
  overflow-y:auto;animation:slideUp .25s ease-out;
  scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent;
}
@media(min-width:641px){.tg-sheet{border-radius:16px;padding:24px;}}
.tg-sheet::-webkit-scrollbar{width:3px;}
.tg-sheet::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px;}
.tg-drag{width:36px;height:4px;background:rgba(255,255,255,.15);border-radius:2px;margin:0 auto 16px;}
@media(min-width:641px){.tg-drag{display:none;}}
.tg-sheet-title{font-size:17px;font-weight:600;color:var(--tg-txt);margin-bottom:18px;}
.tg-s-sec{margin-bottom:20px;}
.tg-s-label{font-size:13px;color:var(--tg-accent);font-weight:500;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px;}
.tg-s-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--tg-divider);}
.tg-s-row:last-child{border-bottom:none;}
.tg-s-body{flex:1;}
.tg-s-title{font-size:15px;color:var(--tg-txt);}
.tg-s-sub{font-size:13px;color:var(--tg-txt2);margin-top:2px;}
.tg-s-inp{width:100%;padding:10px 14px;background:var(--tg-input);border:none;border-radius:10px;
  color:var(--tg-txt);font-family:var(--font);font-size:14px;outline:none;
  transition:box-shadow .2s;margin-top:6px;}
.tg-s-inp:focus{box-shadow:0 0 0 2px rgba(44,165,224,.35);}
.tg-s-inp::placeholder{color:var(--tg-txt2);}
.tg-s-save{padding:10px 20px;background:var(--tg-accent);border:none;border-radius:10px;
  color:#fff;font-family:var(--font);font-size:14px;font-weight:500;cursor:pointer;transition:background .15s;margin-top:8px;}
.tg-s-save:hover{background:var(--tg-accent2);}
.tg-s-logout{width:100%;padding:12px;background:none;border:1px solid var(--tg-red);
  border-radius:10px;color:var(--tg-red);font-family:var(--font);font-size:15px;cursor:pointer;transition:all .15s;}
.tg-s-logout:hover{background:var(--tg-red);color:#fff;}

/* ── TOGGLE ── */
.tog{position:relative;width:51px;height:31px;flex-shrink:0;cursor:pointer;display:inline-block;}
.tog input{opacity:0;width:0;height:0;position:absolute;}
.tog-t{position:absolute;inset:0;background:rgba(255,255,255,.15);border-radius:16px;transition:background .22s;}
.tog input:checked+.tog-t{background:var(--tg-accent);}
.tog-k{position:absolute;top:3px;left:3px;width:25px;height:25px;background:#fff;
  border-radius:50%;transition:transform .22s;pointer-events:none;box-shadow:0 1px 4px rgba(0,0,0,.3);}
.tog input:checked~.tog-k{transform:translateX(20px);}

/* ── VOICE RECORDING ── */
.tg-rec-pill{
  display:flex;align-items:center;gap:8px;padding:6px 14px;
  background:rgba(236,57,66,.15);border-radius:20px;flex:1;
}
.tg-rec-dot{width:8px;height:8px;border-radius:50%;background:var(--tg-red);animation:recblink 1s infinite;}
.tg-rec-time{font-size:14px;color:var(--tg-red);font-family:monospace;}
.tg-rec-cancel{font-size:13px;color:var(--tg-txt2);cursor:pointer;}
.tg-rec-cancel:hover{color:var(--tg-red);}

/* ── CTX MENU ── */
.tg-ctx{
  position:fixed;background:var(--tg-sb);border:1px solid var(--tg-bord);
  border-radius:14px;padding:6px;min-width:170px;z-index:200;
  box-shadow:0 8px 30px rgba(0,0,0,.5);animation:fadeUp .12s ease-out;
}
.tg-ctx-item{
  display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;
  cursor:pointer;font-size:14px;color:var(--tg-txt);transition:background .12s;
}
.tg-ctx-item:hover{background:rgba(255,255,255,.06);}
[data-theme="light"] .tg-ctx-item:hover{background:rgba(0,0,0,.05);}
.tg-ctx-item.danger{color:var(--tg-red);}

/* ── AUTH ── */
.tg-auth{
  min-height:100%;display:flex;align-items:center;justify-content:center;
  background:var(--tg-bg);padding:20px 16px;
}
.tg-auth-card{
  width:100%;max-width:400px;background:var(--tg-sb);border-radius:16px;
  padding:36px 28px;position:relative;overflow:hidden;
  box-shadow:0 20px 60px rgba(0,0,0,.4);animation:fadeUp .35s ease-out;
}
.tg-auth-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--tg-accent);}
.tg-auth-logo{display:flex;flex-direction:column;align-items:center;gap:12px;margin-bottom:8px;}
.tg-auth-icon{width:72px;height:72px;border-radius:50%;background:linear-gradient(135deg,#2CA5E0,#1A8AC4);
  display:flex;align-items:center;justify-content:center;font-size:36px;
  box-shadow:0 8px 24px rgba(44,165,224,.4);}
.tg-auth-appname{font-size:28px;font-weight:700;color:var(--tg-txt);letter-spacing:-.5px;}
.tg-auth-tagline{font-size:13px;color:var(--tg-txt2);text-align:center;margin-bottom:28px;line-height:1.5;}
.tg-server-warn{
  font-size:12px;color:#FFA500;text-align:center;margin-bottom:12px;
  display:flex;align-items:center;justify-content:center;gap:6px;
}
.tg-tabs{display:flex;border-radius:12px;overflow:hidden;margin-bottom:22px;background:var(--tg-input);}
.tg-tab{flex:1;padding:10px;background:none;border:none;color:var(--tg-txt2);
  font-family:var(--font);font-size:14px;font-weight:500;cursor:pointer;transition:all .2s;}
.tg-tab.on{background:var(--tg-accent);color:#fff;border-radius:10px;}
.tg-field{margin-bottom:14px;}
.tg-field label{display:block;font-size:12px;color:var(--tg-txt2);margin-bottom:5px;font-weight:500;}
.tg-fi{width:100%;padding:12px 14px;background:var(--tg-input);border:none;border-radius:10px;
  color:var(--tg-txt);font-family:var(--font);font-size:15px;outline:none;transition:box-shadow .2s;}
.tg-fi:focus{box-shadow:0 0 0 2px rgba(44,165,224,.4);}
.tg-fi::placeholder{color:var(--tg-txt2);}
.tg-pwd-row{position:relative;}
.tg-pwd-row .tg-fi{padding-right:44px;}
.tg-pwd-eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);
  background:none;border:none;cursor:pointer;color:var(--tg-txt2);padding:4px;
  display:flex;align-items:center;}
.tg-pwd-eye:hover{color:var(--tg-accent);}
.tg-hint{font-size:12px;color:var(--tg-txt2);line-height:1.6;margin-bottom:10px;}
.tg-btn{width:100%;padding:14px;background:var(--tg-accent);border:none;border-radius:12px;
  color:#fff;font-family:var(--font);font-size:16px;font-weight:500;cursor:pointer;
  transition:background .15s,transform .1s;margin-top:6px;letter-spacing:.2px;}
.tg-btn:hover{background:var(--tg-accent2);}
.tg-btn:active{transform:scale(.99);}
.tg-btn:disabled{opacity:.5;cursor:not-allowed;}
.tg-err{color:var(--tg-red);font-size:13px;margin-top:10px;text-align:center;}
.tg-switch{font-size:13px;color:var(--tg-txt2);text-align:center;margin-top:14px;cursor:pointer;}
.tg-switch:hover{color:var(--tg-accent);}
.tg-switch span{color:var(--tg-accent);}

/* ── MOBILE ── */
@media(max-width:680px){
  .tg-left{
    position:fixed;top:0;left:0;bottom:0;z-index:100;width:100%;
    transform:translateX(-100%);transition:transform .28s cubic-bezier(.4,0,.2,1);
  }
  .tg-left.open{transform:translateX(0);}
  .tg-right{width:100%;}
  .tg-bubble-wrap{max-width:86%;}
  .tg-msgs{padding:6px 0 2px;}
  .tg-mrow{padding:1px 6px;}
}

/* ── ANIMATIONS ── */
@keyframes fadeUp{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
@keyframes slideUp{from{transform:translateY(100%);}to{transform:translateY(0);}}
@keyframes tgpulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.3;transform:scale(.7);}}
@keyframes recblink{0%,100%{opacity:1;}50%{opacity:.2;}}
@keyframes spin{from{transform:rotate(0deg);}to{transform:rotate(360deg);}}
`;

/* ══ ICONS ════════════════════════════════════════════════════════════════ */
const I = ({d,size=20,fill="none",...p}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill} stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}>{d}</svg>
);
const IBack   = ()=><I size={24} d={<polyline points="15 18 9 12 15 6"/>}/>;
const IMenu   = ()=><I size={22} d={<><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></>}/>;
const IX      = ()=><I size={20} d={<><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></>}/>;
const IGear   = ()=><I size={20} d={<><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></>}/>;
const ISend   = ()=><I size={20} d={<><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2" fill="currentColor" stroke="none"/></>}/>;
const IAttach = ()=><I size={22} d={<path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>}/>;
const IMic    = ()=><I size={22} d={<><path d="M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z"/><path d="M19 10v2a7 7 0 01-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></>}/>;
const ISearch = ()=><I size={18} d={<><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></>}/>;
const IMore   = ()=><I size={22} d={<><circle cx="12" cy="5" r="1" fill="currentColor"/><circle cx="12" cy="12" r="1" fill="currentColor"/><circle cx="12" cy="19" r="1" fill="currentColor"/></>}/>;
const ISun    = ()=><I size={18} d={<><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></>}/>;
const IMoon   = ()=><I size={18} d={<path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>}/>;
const IEyeOn  = ()=><I size={18} d={<><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></>}/>;
const IEyeOff = ()=>(
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>
    <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>
    <line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
);
const IReply  = ()=><I size={16} d={<><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 00-4-4H4"/></>}/>;
const ITrash  = ()=><I size={16} d={<><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a1 1 0 011-1h4a1 1 0 011 1v2"/></>}/>;
const ICopy   = ()=><I size={16} d={<><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></>}/>;
const IPin    = ()=><I size={16} d={<><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 00-1.11-1.79l-1.78-.9A2 2 0 0115 10.76V6h1a2 2 0 000-4H8a2 2 0 000 4h1v4.76a2 2 0 01-1.11 1.79l-1.78.9A2 2 0 005 15.24V17z"/></>}/>;
const IBell   = ()=><I size={18} d={<><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></>}/>;
const IBellOff= ()=>(
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M13.73 21a2 2 0 01-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0118 8"/><path d="M6.26 6.26A5.86 5.86 0 006 8c0 7-3 9-3 9h14"/><path d="M18 8a6 6 0 00-9.33-5"/><line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
);
const IPlay   = ()=><I size={16} fill="currentColor" stroke="none" d={<polygon points="5 3 19 12 5 21 5 3"/>}/>;
const IPause  = ()=><I size={16} d={<><line x1="6" y1="4" x2="6" y2="20"/><line x1="18" y1="4" x2="18" y2="20"/></>}/>;

/* ══ SMALL COMPONENTS ═════════════════════════════════════════════════════ */
function Toggle({ on, onChange }) {
  return (
    <label className="tog">
      <input type="checkbox" checked={on} onChange={e=>onChange(e.target.checked)}/>
      <div className="tog-t"/><div className="tog-k"/>
    </label>
  );
}

function TgAvatar({ name, size=46, online, photo }) {
  const bg = TG_COLORS[colorIdx(name)];
  const dot = Math.round(size*0.26);
  return (
    <div className="tg-av" style={{width:size,height:size}}>
      <div className="tg-av-img" style={{
        width:size,height:size,background:photo?"transparent":bg,
        fontSize:Math.round(size*0.38),
        backgroundImage:photo?`url(${photo})`:"none",
        backgroundSize:"cover",backgroundPosition:"center",
      }}>
        {!photo && initials(name)}
      </div>
      {online!==undefined && <div className={`tg-av-online${online?"":" off"}`} style={{width:dot,height:dot}}/>}
    </div>
  );
}

function BubbleTail({ me }) {
  return (
    <svg className={`tg-tail ${me?"me":"you"}`} viewBox="0 0 11 20">
      <path d="M10 0 Q0 0 0 20 Q10 20 10 12 L10 0Z"/>
    </svg>
  );
}

function Tick({ pending, delivered, seen }) {
  if (pending) return null;
  if (seen)      return <span className="tg-tick t3">✓✓</span>;
  if (delivered) return <span className="tg-tick t2">✓✓</span>;
  return <span className="tg-tick t1">✓</span>;
}

function TypingDots() {
  return (
    <div className="tg-typing">
      <div className="tg-typing-dots">
        <div className="tg-tdot"/><div className="tg-tdot"/><div className="tg-tdot"/>
      </div>
    </div>
  );
}

/* ══ VOICE PLAYER ═════════════════════════════════════════════════════════ */
function VoicePlayer({ src }) {
  const [playing, setPlaying] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dur, setDur] = useState(0);
  const audioRef = useRef(null);

  useEffect(() => {
    const a = new Audio(src);
    audioRef.current = a;
    a.onloadedmetadata = () => setDur(Math.round(a.duration));
    a.ontimeupdate = () => setProgress(a.currentTime / (a.duration||1));
    a.onended = () => { setPlaying(false); setProgress(0); };
    return () => { a.pause(); };
  }, [src]);

  const toggle = () => {
    const a = audioRef.current;
    if (playing) { a.pause(); setPlaying(false); }
    else { a.play(); setPlaying(true); }
  };

  const bars = Array.from({length:28},(_,i) => {
    const h = 4 + Math.abs(Math.sin(i*0.8+1)*14);
    const filled = i/28 <= progress;
    return (
      <div key={i} className="tg-voice-dot" style={{
        height:h, background: filled?"var(--tg-accent)":"rgba(255,255,255,.3)"
      }}/>
    );
  });

  const fmt = s => `${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;
  return (
    <div className="tg-voice">
      <button className="tg-voice-btn" onClick={toggle}>{playing?<IPause/>:<IPlay/>}</button>
      <div className="tg-voice-bar">{bars}</div>
      <span className="tg-voice-dur">{fmt(dur)}</span>
    </div>
  );
}

/* ══ BUBBLE CONTENT ═══════════════════════════════════════════════════════ */
function BubbleContent({ msg }) {
  if (msg.deleted) return <em style={{opacity:.6,fontSize:13}}>Message deleted</em>;
  try {
    const p = JSON.parse(msg.text);
    if (p.type==="voice")
      return <VoicePlayer src={p.data}/>;
    if (p.type==="file") {
      if (p.mime?.startsWith("image/"))
        return <div><img src={p.data} alt={p.name}/><div style={{fontSize:11,color:"rgba(255,255,255,.6)",marginTop:4}}>{p.name}</div></div>;
      return (
        <div className="tg-file-chip" onClick={()=>{const a=document.createElement("a");a.href=p.data;a.download=p.name;a.click();}}>
          <div className="tg-file-ico">📎</div>
          <div className="tg-file-info">
            <div className="tg-file-name">{p.name}</div>
            <div className="tg-file-size">{(p.size/1024).toFixed(1)} KB · Tap to download</div>
          </div>
        </div>
      );
    }
  } catch {}
  return <>{msg.text}</>;
}

/* ══ SETTINGS ═════════════════════════════════════════════════════════════ */
function Settings({ user, theme, onTheme, onLogout, onClose, status, onSaveStatus,
  soundOn, setSoundOn, pushOn, setPushOn, photo, onPhotoChange }) {
  const [localStatus, setLocalStatus] = useState(status);
  const fileRef = useRef();

  const handlePhoto = e => {
    const f = e.target.files?.[0]; if (!f) return;
    const r = new FileReader();
    r.onload = ev => onPhotoChange(ev.target.result);
    r.readAsDataURL(f);
  };

  const togglePush = async v => {
    if (v) {
      if (!("Notification" in window)) return;
      const p = await Notification.requestPermission();
      if (p!=="granted") return;
    }
    setPushOn(v); LS.set("sa_push",v);
  };

  return (
    <div className="tg-scrim" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="tg-sheet">
        <div className="tg-drag"/>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20}}>
          <div className="tg-sheet-title">Settings</div>
          <button className="ibtn" onClick={onClose}><IX/></button>
        </div>

        {/* Profile */}
        <div className="tg-s-sec">
          <div className="tg-s-label">Profile</div>
          <div style={{display:"flex",alignItems:"center",gap:14,marginBottom:14}}>
            <div style={{position:"relative",cursor:"pointer"}} onClick={()=>fileRef.current.click()}>
              <TgAvatar name={user?.display_name} size={56} photo={photo}/>
              <div style={{position:"absolute",inset:0,borderRadius:"50%",background:"rgba(0,0,0,.4)",
                display:"flex",alignItems:"center",justifyContent:"center",opacity:0,transition:"opacity .2s"}}
                onMouseEnter={e=>e.currentTarget.style.opacity=1}
                onMouseLeave={e=>e.currentTarget.style.opacity=0}>📷</div>
            </div>
            <input ref={fileRef} type="file" accept="image/*" style={{display:"none"}} onChange={handlePhoto}/>
            <div>
              <div style={{fontSize:16,fontWeight:600,color:"var(--tg-txt)"}}>{user?.display_name}</div>
              <div style={{fontSize:13,color:"var(--tg-txt2)",marginTop:2}}>@{user?.username}</div>
            </div>
          </div>
          <input className="tg-s-inp" value={localStatus} onChange={e=>setLocalStatus(e.target.value)}
            placeholder="Status (What's on your mind?)" maxLength={80}/>
          <div style={{display:"flex",justifyContent:"space-between",marginTop:6}}>
            <span style={{fontSize:12,color:"var(--tg-txt3)"}}>{localStatus.length}/80</span>
            <button className="tg-s-save" onClick={()=>{onSaveStatus(localStatus);onClose();}}>Save</button>
          </div>
        </div>

        {/* Notifications */}
        <div className="tg-s-sec">
          <div className="tg-s-label">Notifications</div>
          <div className="tg-s-row">
            <div className="tg-s-body"><div className="tg-s-title">Sound</div><div className="tg-s-sub">Ping on new message</div></div>
            <Toggle on={soundOn} onChange={v=>{setSoundOn(v);LS.set("sa_sound",v);}}/>
          </div>
          <div className="tg-s-row">
            <div className="tg-s-body"><div className="tg-s-title">Push notifications</div><div className="tg-s-sub">When app is in background</div></div>
            <Toggle on={pushOn} onChange={togglePush}/>
          </div>
        </div>

        {/* Appearance */}
        <div className="tg-s-sec">
          <div className="tg-s-label">Appearance</div>
          <div className="tg-s-row">
            <div className="tg-s-body"><div className="tg-s-title">Theme</div><div className="tg-s-sub">{theme==="light"?"Light mode":"Dark mode"}</div></div>
            <div style={{display:"flex",alignItems:"center",gap:8,color:"var(--tg-txt2)"}}>
              <IMoon/><Toggle on={theme==="light"} onChange={v=>onTheme(v?"light":"dark")}/><ISun/>
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="tg-s-sec">
          <div className="tg-s-label">Security</div>
          <div className="tg-s-row">
            <div className="tg-s-body"><div className="tg-s-title">Encryption</div><div className="tg-s-sub">RSA-OAEP 2048 · AES-GCM 256 · PBKDF2</div></div>
            <span style={{fontSize:11,color:"var(--tg-accent)",padding:"3px 8px",border:"1px solid rgba(44,165,224,.3)",borderRadius:20}}>E2EE</span>
          </div>
        </div>

        {/* Account */}
        <div className="tg-s-sec">
          <div className="tg-s-label">Account</div>
          <button className="tg-s-logout" onClick={onLogout}>Sign out</button>
        </div>
      </div>
    </div>
  );
}

/* ══ AUTH PAGE ════════════════════════════════════════════════════════════ */
function AuthPage({ tab, setTab, fields, setFields, err, busy, onLogin, onRegister, serverReady }) {
  const [showPwd, setShowPwd] = useState(false);
  const set = k => e => setFields(f=>({...f,[k]:e.target.value}));
  const submit = tab==="login" ? onLogin : onRegister;
  return (
    <div className="tg-auth">
      <div className="tg-auth-card">
        <div className="tg-auth-logo">
          <div className="tg-auth-icon">✈️</div>
          <div className="tg-auth-appname">SafeApp</div>
        </div>
        <div className="tg-auth-tagline">
          Fast. Secure. Private.<br/>End-to-end encrypted messaging.
        </div>
        {!serverReady && (
          <div className="tg-server-warn">
            <span style={{width:6,height:6,borderRadius:"50%",background:"#FFA500",display:"inline-block",animation:"recblink 1s infinite"}}/>
            Connecting to server…
          </div>
        )}
        <div className="tg-tabs">
          <button className={`tg-tab${tab==="login"?" on":""}`} onClick={()=>setTab("login")}>Sign in</button>
          <button className={`tg-tab${tab==="register"?" on":""}`} onClick={()=>setTab("register")}>Register</button>
        </div>
        {tab==="register" && (
          <div className="tg-field"><label>Display name</label>
            <input className="tg-fi" value={fields.display_name} onChange={set("display_name")} placeholder="Your name" autoFocus/>
          </div>
        )}
        <div className="tg-field"><label>Username</label>
          <input className="tg-fi" value={fields.username} onChange={set("username")}
            placeholder="username" autoFocus={tab==="login"} onKeyDown={e=>e.key==="Enter"&&submit()}/>
        </div>
        <div className="tg-field"><label>Password</label>
          <div className="tg-pwd-row">
            <input className="tg-fi" type={showPwd?"text":"password"} value={fields.password}
              onChange={set("password")} placeholder="Password" onKeyDown={e=>e.key==="Enter"&&submit()}/>
            <button className="tg-pwd-eye" type="button" tabIndex={-1} onClick={()=>setShowPwd(v=>!v)}>
              {showPwd?<IEyeOn/>:<IEyeOff/>}
            </button>
          </div>
        </div>
        {tab==="register" && <p className="tg-hint">Keys generated in browser. Password wraps private key via PBKDF2→AES-GCM. Server never sees plaintext.</p>}
        <button className="tg-btn" disabled={busy||!serverReady} onClick={submit}>
          {!serverReady?"Connecting…":busy?(tab==="login"?"Signing in…":"Creating account…"):(tab==="login"?"Sign in":"Create account")}
        </button>
        {err && (
          <div className="tg-err">
            {err}
            {(err.includes("reach")||err.includes("timed")||err.includes("fetch")) && (
              <div style={{marginTop:4,fontSize:12,color:"#FFA500"}}>⚠ Server cold start (~10s). Try again.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ══ UNLOCK PAGE ══════════════════════════════════════════════════════════ */
function UnlockPage({ savedUser, onUnlock, onSwitch, err, busy }) {
  const [pwd, setPwd] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const photo = LS.get(`sa_photo_${savedUser?.id}`);
  return (
    <div className="tg-auth">
      <div className="tg-auth-card">
        <div style={{display:"flex",justifyContent:"center",marginBottom:16}}>
          <TgAvatar name={savedUser?.display_name} size={80} photo={photo}/>
        </div>
        <div className="tg-auth-tagline" style={{marginBottom:24,fontSize:15}}>
          <strong style={{color:"var(--tg-txt)",display:"block",fontSize:18,marginBottom:4}}>
            {savedUser?.display_name}
          </strong>
          @{savedUser?.username}
        </div>
        <div className="tg-field"><label>Password to unlock</label>
          <div className="tg-pwd-row">
            <input className="tg-fi" type={showPwd?"text":"password"} value={pwd}
              onChange={e=>setPwd(e.target.value)} placeholder="Your password" autoFocus
              onKeyDown={e=>e.key==="Enter"&&pwd&&onUnlock(pwd)}/>
            <button className="tg-pwd-eye" type="button" tabIndex={-1} onClick={()=>setShowPwd(v=>!v)}>
              {showPwd?<IEyeOn/>:<IEyeOff/>}
            </button>
          </div>
        </div>
        <button className="tg-btn" disabled={busy||!pwd} onClick={()=>onUnlock(pwd)}>
          {busy?"Unlocking…":"Unlock"}
        </button>
        {err && <div className="tg-err">{err}</div>}
        <div className="tg-switch" onClick={onSwitch}>
          Switch account? <span>Sign in</span>
        </div>
      </div>
    </div>
  );
}

/* ══ MAIN APP ══════════════════════════════════════════════════════════════ */
function AppShell({
  user, convos, active, msgs, loadingMsgs, draft, setDraft, sending,
  searchQ, setSearchQ, searchRes, wsOnline, onlineUsers, lastSeenMap,
  theme, onTheme, onOpenConvo, onSend, onLogout, bottomRef, inputRef,
  status, onSaveStatus, unreadMap, soundOn, setSoundOn, pushOn, setPushOn,
  photo, onPhotoChange, onLoadMore, hasMore, typingUsers, onTyping,
  pinnedContacts, onTogglePin, mutedConvos, onToggleMute,
  reactions, onReact, onDeleteMsg, onReply, replyTo, setReplyTo,
  msgSearch, setMsgSearch, showMsgSearch, setShowMsgSearch
}) {
  const [leftOpen, setLeftOpen] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [ctxMenu, setCtxMenu] = useState(null);
  const [emojiPicker, setEmojiPicker] = useState(null);
  const [isRecording, setIsRecording] = useState(false);
  const [recTime, setRecTime] = useState(0);
  const recTimerRef = useRef(null);
  const mediaRecRef = useRef(null);
  const recChunks   = useRef([]);
  const taRef       = useRef(null);
  const fileRef     = useRef(null);

  const toU = x => ({ user_id:x.user_id||x.id, display_name:x.display_name, username:x.username, public_key:x.public_key });
  const list = searchQ.trim() ? searchRes : [
    ...convos.filter(c=>pinnedContacts.has(c.user_id||c.id)),
    ...convos.filter(c=>!pinnedContacts.has(c.user_id||c.id)),
  ];
  const isOnline = id => onlineUsers.has(id);

  const handleOpenConvo = cu => { setLeftOpen(false); onOpenConvo(cu); };

  const onKey = e => {
    if (e.key==="Enter"&&!e.shiftKey){ e.preventDefault(); onSend(); return; }
    onTyping();
  };

  const autoResize = () => {
    const el = taRef.current; if (!el) return;
    el.style.height="auto";
    el.style.height=Math.min(el.scrollHeight,140)+"px";
  };

  // voice recording
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio:true });
      const mr = new MediaRecorder(stream);
      mediaRecRef.current = mr; recChunks.current = [];
      mr.ondataavailable = e => recChunks.current.push(e.data);
      mr.onstop = () => {
        const blob = new Blob(recChunks.current, { type:"audio/webm" });
        const reader = new FileReader();
        reader.onload = ev => {
          const payload = JSON.stringify({ type:"voice", data:ev.target.result });
          onSend(payload);
        };
        reader.readAsDataURL(blob);
        stream.getTracks().forEach(t=>t.stop());
      };
      mr.start(); setIsRecording(true); setRecTime(0);
      recTimerRef.current = setInterval(()=>setRecTime(t=>t+1),1000);
    } catch {}
  };

  const stopRecording = () => {
    if (mediaRecRef.current?.state==="recording") mediaRecRef.current.stop();
    clearInterval(recTimerRef.current); setIsRecording(false);
  };

  const cancelRecording = () => {
    if (mediaRecRef.current?.state==="recording") {
      mediaRecRef.current.ondataavailable = null;
      mediaRecRef.current.onstop = null;
      mediaRecRef.current.stop();
    }
    clearInterval(recTimerRef.current); setIsRecording(false);
  };

  const handleFileAttach = async e => {
    const f = e.target.files?.[0]; if (!f) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const payload = JSON.stringify({ type:"file", name:f.name, mime:f.type, size:f.size, data:ev.target.result });
      onSend(payload);
    };
    reader.readAsDataURL(f);
    e.target.value="";
  };

  // ctx menu
  const openCtx = (e, msg) => {
    e.preventDefault();
    const x = e.clientX||e.touches?.[0]?.clientX||200;
    const y = e.clientY||e.touches?.[0]?.clientY||300;
    setCtxMenu({ msg, x:Math.min(x,window.innerWidth-180), y:Math.min(y,window.innerHeight-240) });
  };
  useEffect(() => {
    if (!ctxMenu) return;
    const h = ()=>setCtxMenu(null);
    setTimeout(()=>document.addEventListener("click",h),10);
    return ()=>document.removeEventListener("click",h);
  },[ctxMenu]);

  const fmtRecTime = s => `${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;

  // group messages
  const displayMsgs = msgSearch.trim()
    ? msgs.filter(m=>m.text?.toLowerCase().includes(msgSearch.toLowerCase()))
    : msgs;
  const grouped = [];
  let lastD = null;
  for (const m of displayMsgs) {
    const d = new Date(m.created_at).toDateString();
    if (d!==lastD){ grouped.push({_sep:true,iso:m.created_at}); lastD=d; }
    grouped.push(m);
  }

  return (
    <div className="tg-shell">
      {/* ── Left panel ── */}
      <div className={`tg-left${leftOpen?" open":""}`}>
        {/* Top bar */}
        <div className="tg-topbar">
          <button className="ibtn" onClick={()=>setShowSettings(true)}><IGear/></button>
          <div className="tg-topbar-title">SafeApp</div>
          <div style={{display:"flex",alignItems:"center",gap:2,color:wsOnline?"var(--tg-green)":"var(--tg-txt2)",fontSize:11,marginRight:4}}>
            <div style={{width:6,height:6,borderRadius:"50%",background:wsOnline?"var(--tg-green)":"var(--tg-txt2)"}}/>
            {wsOnline?"":"offline"}
          </div>
          <button className="ibtn" onClick={()=>setShowSettings(true)}><IMore/></button>
        </div>

        {/* Search */}
        <div className="tg-search-bar">
          <div className="tg-search-wrap">
            <span className="tg-search-ico"><ISearch/></span>
            <input className="tg-search-inp" placeholder="Search" value={searchQ} onChange={e=>setSearchQ(e.target.value)}/>
          </div>
        </div>

        {/* List */}
        <div className="tg-list">
          {pinnedContacts.size>0 && !searchQ && <div className="tg-divider-label">📌 Pinned</div>}
          {list.map(item => {
            const cu = toU(item);
            const online = isOnline(cu.user_id);
            const unread = unreadMap[cu.user_id]||0;
            const muted  = mutedConvos.has(cu.user_id);
            return (
              <div key={cu.user_id} className={`tg-list-item${active?.user_id===cu.user_id?" active":""}`}
                onClick={()=>handleOpenConvo(cu)}>
                <TgAvatar name={cu.display_name} size={50} online={online}
                  photo={LS.get(`sa_photo_${cu.user_id}`)}/>
                <div className="tg-list-info">
                  <div className="tg-list-row1">
                    <div className="tg-list-name">{cu.display_name}</div>
                    <div className="tg-list-time">{item.last_message_at?fmtLabel(item.last_message_at):""}</div>
                  </div>
                  <div className="tg-list-row2">
                    <div className="tg-list-preview">
                      {online?<span style={{color:"var(--tg-green)"}}>online</span>:`@${cu.username}`}
                    </div>
                    {unread>0&&!muted&&<div className="tg-list-count">{unread>99?"99+":unread}</div>}
                    {muted&&<div className="tg-list-mute">🔕</div>}
                  </div>
                </div>
              </div>
            );
          })}
          {list.length===0&&searchQ&&(
            <div style={{padding:"24px",textAlign:"center",fontSize:14,color:"var(--tg-txt2)"}}>No users found</div>
          )}
          {!searchQ&&convos.length===0&&(
            <div style={{padding:"40px 20px",textAlign:"center",fontSize:14,color:"var(--tg-txt2)",lineHeight:1.8}}>
              No conversations yet.<br/>Search for a user to start chatting.
            </div>
          )}
        </div>

        {/* Me bar */}
        <div className="tg-me-bar">
          <TgAvatar name={user?.display_name} size={36} photo={photo}/>
          <div style={{flex:1,minWidth:0}}>
            <div className="tg-me-name">{user?.display_name}</div>
            <div className="tg-me-status">{status||`@${user?.username}`}</div>
          </div>
          <span style={{fontSize:11,color:"var(--tg-accent)",padding:"2px 8px",border:"1px solid rgba(44,165,224,.3)",borderRadius:12}}>E2EE</span>
        </div>
      </div>

      {/* ── Right panel ── */}
      <div className="tg-right">
        <div className="tg-chat-bg"/>

        {!active ? (
          <>
            <div className="tg-chat-head">
              <button className="ibtn" style={{marginLeft:4}} onClick={()=>setLeftOpen(true)}><IMenu/></button>
            </div>
            <div className="tg-empty">
              <div className="tg-empty-icon">✈️</div>
              <div className="tg-empty-title">SafeApp</div>
              <div className="tg-empty-sub">Select a conversation from the left panel to start chatting securely.</div>
            </div>
          </>
        ) : (
          <>
            {/* Chat header */}
            <div className="tg-chat-head">
              <button className="ibtn" style={{marginLeft:4}} onClick={()=>setLeftOpen(true)}><IBack/></button>
              <TgAvatar name={active.display_name} size={36} online={isOnline(active.user_id)}
                photo={LS.get(`sa_photo_${active.user_id}`)}/>
              <div className="tg-chat-head-info" onClick={()=>setShowSettings(true)}>
                <div className="tg-chat-head-name">{active.display_name}</div>
                <div className="tg-chat-head-sub">
                  {isOnline(active.user_id)?"online"
                    :lastSeenMap[active.user_id]?fmtLastSeen(lastSeenMap[active.user_id])
                    :`@${active.username}`}
                </div>
              </div>
              <button className="ibtn" onClick={()=>setShowMsgSearch(v=>!v)}><ISearch/></button>
              <button className="ibtn" onClick={()=>onToggleMute(active.user_id)}>
                {mutedConvos.has(active.user_id)?<IBellOff/>:<IBell/>}
              </button>
              <button className="ibtn" style={{marginRight:4}} onClick={()=>setShowSettings(true)}><IMore/></button>
            </div>

            {/* Message search */}
            {showMsgSearch && (
              <div className="tg-msg-search">
                <input placeholder="Search messages…" value={msgSearch} onChange={e=>setMsgSearch(e.target.value)} autoFocus/>
                <button className="ibtn" onClick={()=>{setShowMsgSearch(false);setMsgSearch("");}}>
                  <IX/>
                </button>
              </div>
            )}

            {/* Messages */}
            {loadingMsgs ? (
              <div className="tg-loading">
                <span style={{animation:"spin 1s linear infinite",display:"inline-block",fontSize:20,marginRight:10}}>⏳</span>
                Decrypting messages…
              </div>
            ) : (
              <div className="tg-msgs">
                {hasMore&&!msgSearch&&(
                  <button className="tg-load-more" onClick={onLoadMore}>Load earlier messages</button>
                )}
                {grouped.length===0&&!msgSearch&&(
                  <div style={{margin:"auto",textAlign:"center",color:"var(--tg-txt2)",fontSize:14,lineHeight:1.8,padding:20}}>
                    No messages yet.<br/>Say hello! 👋
                  </div>
                )}
                {grouped.map((item,i) => {
                  if (item._sep) return (
                    <div key={`sep${i}`} className="tg-day-sep">
                      <span>{new Date(item.iso).toLocaleDateString([],{weekday:"long",month:"long",day:"numeric"})}</span>
                    </div>
                  );
                  const me = item.isSender;
                  const msgReactions = reactions[item.id]||{};
                  return (
                    <div key={item.id} className={`tg-mrow ${me?"me":"you"}`}
                      onContextMenu={e=>openCtx(e,item)}
                      onTouchStart={e=>{
                        const t=setTimeout(()=>openCtx(e,item),500);
                        document.addEventListener("touchend",()=>clearTimeout(t),{once:true});
                      }}>
                      <div className="tg-bubble-wrap">
                        <span className="ts-full" style={{display:"none"}}>{fmtFull(item.created_at)}</span>

                        {emojiPicker===item.id && (
                          <div className="tg-emoji-picker">
                            {EMOJI_LIST.map(em=>(
                              <span key={em} className="tg-ep-btn"
                                onClick={()=>{onReact(item.id,em);setEmojiPicker(null);}}>{em}</span>
                            ))}
                          </div>
                        )}

                        <button className="tg-react-btn" onClick={()=>setEmojiPicker(p=>p===item.id?null:item.id)}>😊</button>

                        {item.replyTo && (
                          <div className="tg-reply">
                            <div className="tg-reply-name">{me?"You":active.display_name}</div>
                            <div className="tg-reply-text">{item.replyToText||"Message"}</div>
                          </div>
                        )}

                        <div className={`tg-bubble${item.pending?" pending":""}${item.deleted?" deleted":""}`}>
                          <BubbleContent msg={item}/>
                          <div className="tg-meta">
                            {fmtTime(item.created_at)}
                            {me&&<Tick pending={item.pending} delivered={item.delivered} seen={item.seen}/>}
                          </div>
                        </div>
                        <BubbleTail me={me}/>

                        {Object.keys(msgReactions).length>0&&(
                          <div className="tg-reactions">
                            {Object.entries(msgReactions).map(([em,users])=>(
                              <span key={em} className={`tg-r-chip${users.includes("me")?" mine":""}`}
                                onClick={()=>onReact(item.id,em)}>
                                {em}{users.length>1?` ${users.length}`:""}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
                {typingUsers.has(active.user_id)&&<TypingDots/>}
                <div ref={bottomRef}/>
              </div>
            )}

            {/* Input */}
            <div className="tg-input-area">
              {replyTo&&(
                <div className="tg-reply-preview">
                  <div className="tg-reply-preview-body">
                    <div className="tg-reply-preview-name">Reply to {replyTo.isSender?"yourself":active.display_name}</div>
                    <div className="tg-reply-preview-text">{replyTo.text}</div>
                  </div>
                  <button className="ibtn" onClick={()=>setReplyTo(null)}><IX/></button>
                </div>
              )}
              <div className="tg-input-row">
                <input ref={fileRef} type="file" style={{display:"none"}} onChange={handleFileAttach}/>
                {isRecording ? (
                  <>
                    <div className="tg-rec-pill">
                      <div className="tg-rec-dot"/>
                      <span className="tg-rec-time">{fmtRecTime(recTime)}</span>
                      <span className="tg-rec-cancel" onClick={cancelRecording}>✕ Cancel</span>
                    </div>
                    <button className="tg-send-btn" onClick={stopRecording}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                        <rect x="4" y="4" width="16" height="16" rx="2"/>
                      </svg>
                    </button>
                  </>
                ) : (
                  <>
                    <button className="tg-attach-btn" onClick={()=>fileRef.current.click()}><IAttach/></button>
                    <textarea
                      ref={el=>{taRef.current=el; if(inputRef) inputRef.current=el;}}
                      className="tg-textarea" rows={1}
                      placeholder="Message"
                      value={draft} onChange={e=>{setDraft(e.target.value);autoResize();}}
                      onKeyDown={onKey}/>
                    {draft.trim() ? (
                      <button className="tg-send-btn" onClick={()=>onSend()} disabled={sending}><ISend/></button>
                    ) : (
                      <button className="tg-send-btn voice" onClick={startRecording}><IMic/></button>
                    )}
                  </>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Context menu */}
      {ctxMenu&&(
        <div className="tg-ctx" style={{left:ctxMenu.x,top:ctxMenu.y}}>
          <div className="tg-ctx-item" onClick={()=>{onReply(ctxMenu.msg);setCtxMenu(null);}}>
            <IReply/> Reply
          </div>
          <div className="tg-ctx-item" onClick={()=>{setEmojiPicker(ctxMenu.msg.id);setCtxMenu(null);}}>
            😊 React
          </div>
          <div className="tg-ctx-item" onClick={()=>{
            navigator.clipboard?.writeText(ctxMenu.msg.text).catch(()=>{});
            setCtxMenu(null);
          }}>
            <ICopy/> Copy
          </div>
          <div className="tg-ctx-item" onClick={()=>{onTogglePin(active.user_id);setCtxMenu(null);}}>
            <IPin/> {pinnedContacts.has(active.user_id)?"Unpin":"Pin"} contact
          </div>
          {ctxMenu.msg.isSender&&!ctxMenu.msg.deleted&&(
            <div className="tg-ctx-item danger" onClick={()=>{onDeleteMsg(ctxMenu.msg.id);setCtxMenu(null);}}>
              <ITrash/> Delete
            </div>
          )}
        </div>
      )}

      {showSettings&&(
        <Settings user={user} theme={theme} onTheme={onTheme} onLogout={onLogout}
          onClose={()=>setShowSettings(false)} status={status} onSaveStatus={onSaveStatus}
          soundOn={soundOn} setSoundOn={setSoundOn} pushOn={pushOn} setPushOn={setPushOn}
          photo={photo} onPhotoChange={onPhotoChange}/>
      )}
    </div>
  );
}

/* ══ ROOT ══════════════════════════════════════════════════════════════════ */
export default function SafeApp() {
  const applyTheme = t => { document.documentElement.setAttribute("data-theme",t); return t; };
  const [theme, setTheme] = useState(()=>applyTheme(LS.get("sa_theme")||"dark"));
  const onTheme = t => { setTheme(applyTheme(t)); LS.set("sa_theme",t); };
  const [serverReady, setServerReady] = useState(false);

  useEffect(()=>{ wakeServer().then(()=>setServerReady(true)).catch(()=>{}); },[]);

  const [screen,   setScreen]   = useState(()=>SS.load()?"unlock":"auth");
  const [authTab,  setAuthTab]  = useState("login");
  const [fields,   setFields]   = useState({username:"",display_name:"",password:""});
  const [authErr,  setAuthErr]  = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [user,     setUser]     = useState(null);
  const tok     = useRef({access:null,refresh:null});
  const privKey = useRef(null);
  const [convos,    setConvos]    = useState([]);
  const [active,    setActive]    = useState(null);
  const activeRef                 = useRef(null);
  const [msgs,      setMsgs]      = useState([]);
  const [loadingMsgs,setLoadingMsgs]=useState(false);
  const [hasMore,   setHasMore]   = useState(false);
  const [draft,     setDraft]     = useState("");
  const [sending,   setSending]   = useState(false);
  const [searchQ,   setSearchQ]   = useState("");
  const [searchRes, setSearchRes] = useState([]);
  const wsRef = useRef(null);
  const [wsOnline,   setWsOnline]   = useState(false);
  const [onlineUsers,setOnlineUsers]= useState(new Set());
  const [lastSeenMap,setLastSeenMap]= useState({});
  const [typingUsers,setTypingUsers]= useState(new Set());
  const typingTimers = useRef({});
  const [status,    setStatus]    = useState("");
  const [unreadMap, setUnreadMap] = useState({});
  const [soundOn,   setSoundOn]   = useState(()=>LS.get("sa_sound")!==false);
  const [pushOn,    setPushOn]    = useState(()=>LS.get("sa_push")===true);
  const [photo,     setPhoto]     = useState(null);
  const [reactions, setReactions] = useState({});
  const [replyTo,   setReplyTo]   = useState(null);
  const [msgSearch, setMsgSearch] = useState("");
  const [showMsgSearch,setShowMsgSearch] = useState(false);
  const [pinnedContacts,setPinnedContacts] = useState(()=>new Set(LS.get("sa_pinned")||[]));
  const [mutedConvos,   setMutedConvos]    = useState(()=>new Set(LS.get("sa_muted")||[]));
  const bottomRef = useRef(null);
  const inputRef  = useRef(null);

  useEffect(()=>{ activeRef.current=active; },[active]);
  useEffect(()=>{ if(user?.id){ setStatus(LS.get(`sa_status_${user.id}`)||""); setPhoto(LS.get(`sa_photo_${user.id}`)); }},[user?.id]);

  const onPhotoChange  = url => { setPhoto(url); LS.set(`sa_photo_${user?.id}`,url); };
  const onSaveStatus   = val => { LS.set(`sa_status_${user?.id}`,val); setStatus(val); };
  const onTogglePin    = uid => { setPinnedContacts(s=>{ const n=new Set(s); n.has(uid)?n.delete(uid):n.add(uid); LS.set("sa_pinned",[...n]); return n; }); };
  const onToggleMute   = uid => { setMutedConvos(s=>{ const n=new Set(s); n.has(uid)?n.delete(uid):n.add(uid); LS.set("sa_muted",[...n]); return n; }); };
  const onReact        = (id,em) => { setReactions(r=>{ const c={...r}; if(!c[id]) c[id]={}; const u=c[id][em]||[]; c[id][em]=u.includes("me")?u.filter(x=>x!=="me"):[...u,"me"]; return c; }); };
  const onDeleteMsg    = id => setMsgs(p=>p.map(m=>m.id===id?{...m,deleted:true,text:""}:m));
  const onReply        = msg => setReplyTo(msg);

  const sendTyping = useCallback(()=>{
    if(wsRef.current?.readyState===WebSocket.OPEN&&activeRef.current)
      wsRef.current.send(JSON.stringify({event:"typing",to:activeRef.current.user_id}));
  },[]);
  const onTyping = useCallback(()=>sendTyping(),[sendTyping]);

  const refreshAccess = useCallback(async()=>{
    try{ const d=await api("POST","/auth/refresh",{refresh_token:tok.current.refresh}); tok.current.access=d.access_token; return d.access_token; }
    catch{ SS.clear(); setScreen("auth"); return null; }
  },[]);

  const loadConvos = useCallback(async()=>{
    if(!tok.current.access) return;
    try{ setConvos(await api("GET","/conversations",null,tok.current.access)); }catch{}
  },[]);
  useEffect(()=>{ if(screen==="app") loadConvos(); },[screen,loadConvos]);

  const connectWs = useCallback(()=>{
    if(!tok.current.access) return;
    const ws = new WebSocket(`${BASE.replace("https","wss")}/ws?token=${tok.current.access}`);
    wsRef.current=ws;
    ws.onopen=()=>setWsOnline(true);
    ws.onclose=async e=>{
      setWsOnline(false);
      if(e.code===4001){ const nt=await refreshAccess(); if(nt) setTimeout(connectWs,500); }
      else if(e.code===4003){ SS.clear(); setScreen("auth"); }
      else setTimeout(connectWs,3000);
    };
    ws.onmessage=async e=>{
      try{
        const msg=JSON.parse(e.data);
        if(msg.event==="message.receive"&&privKey.current){
          let text="[encrypted]";
          try{ text=await decryptMsg(msg.payload,privKey.current,false); }catch{}
          const m={id:msg.id,from_user_id:msg.from_user_id,to_user_id:msg.to_user_id,text,isSender:false,delivered:true,seen:false,created_at:msg.created_at};
          if(activeRef.current?.user_id===msg.from_user_id){ setMsgs(p=>[...p,{...m,seen:true}]); }
          else{
            setUnreadMap(u=>({...u,[msg.from_user_id]:(u[msg.from_user_id]||0)+1}));
            if(!mutedConvos.has(msg.from_user_id)){ if(soundOn) playPing(); }
          }
          loadConvos();
        }
        if(msg.event==="typing"){
          const uid=msg.from_user_id||msg.user_id;
          setTypingUsers(s=>{ const n=new Set(s); n.add(uid); return n; });
          clearTimeout(typingTimers.current[uid]);
          typingTimers.current[uid]=setTimeout(()=>setTypingUsers(s=>{ const n=new Set(s); n.delete(uid); return n; }),3000);
        }
        if(msg.event==="user.online") setOnlineUsers(s=>{ const n=new Set(s); n.add(msg.user_id); return n; });
        if(msg.event==="user.offline"){ setOnlineUsers(s=>{ const n=new Set(s); n.delete(msg.user_id); return n; }); setLastSeenMap(m=>({...m,[msg.user_id]:new Date().toISOString()})); }
      }catch{}
    };
  },[refreshAccess,loadConvos,soundOn]);

  useEffect(()=>{
    if(screen==="app"){ connectWs(); const iv=setInterval(refreshAccess,14*60*1000); return()=>{ clearInterval(iv); wsRef.current?.close(); }; }
  },[screen,connectWs,refreshAccess]);

  useEffect(()=>{ bottomRef.current?.scrollIntoView({behavior:"smooth"}); },[msgs]);

  useEffect(()=>{
    if(!searchQ.trim()){ setSearchRes([]); return; }
    const t=setTimeout(async()=>{ try{ setSearchRes(await api("GET",`/users/search?q=${encodeURIComponent(searchQ)}`,null,tok.current.access)); }catch{} },350);
    return()=>clearTimeout(t);
  },[searchQ]);

  const openConvo=useCallback(async cu=>{
    setActive(cu); setMsgs([]); setLoadingMsgs(true); setSearchQ(""); setSearchRes([]);
    setUnreadMap(u=>({...u,[cu.user_id]:0})); setReplyTo(null); setHasMore(false);
    try{
      let pk=cu.public_key;
      if(!pk){ const d=await api("GET",`/users/${cu.user_id}/public-key`,null,tok.current.access); pk=d.public_key; setActive(a=>({...a,public_key:pk})); cu={...cu,public_key:pk}; }
      const history=await api("GET",`/conversations/${cu.user_id}/messages?limit=50`,null,tok.current.access);
      setHasMore(history.length===50);
      const me=user?.id;
      const dec=await Promise.allSettled(history.map(async m=>{
        const isSender=m.from_user_id===me; let text="[encrypted]";
        try{ text=await decryptMsg(m.payload,privKey.current,isSender); }catch{}
        return{...m,text,isSender,seen:!isSender};
      }));
      setMsgs(dec.map(r=>r.value).filter(Boolean).reverse());
    }catch(err){ console.error(err); }
    setLoadingMsgs(false);
    setTimeout(()=>inputRef.current?.focus(),100);
  },[user]);

  const onLoadMore=useCallback(async()=>{
    if(!active||!msgs.length) return;
    const oldest=msgs[0]?.created_at; if(!oldest) return;
    try{
      const more=await api("GET",`/conversations/${active.user_id}/messages?limit=50&before=${encodeURIComponent(oldest)}`,null,tok.current.access);
      setHasMore(more.length===50);
      const me=user?.id;
      const dec=await Promise.allSettled(more.map(async m=>{
        const isSender=m.from_user_id===me; let text="[encrypted]";
        try{ text=await decryptMsg(m.payload,privKey.current,isSender); }catch{}
        return{...m,text,isSender,seen:!isSender};
      }));
      setMsgs(p=>[...dec.map(r=>r.value).filter(Boolean).reverse(),...p]);
    }catch{}
  },[active,msgs,user]);

  const sendMsg=async(override)=>{
    const text=(override||draft).trim(); if(!text||!active||sending) return;
    if(!override){ setDraft(""); if(inputRef.current){ inputRef.current.style.height="auto"; } }
    setSending(true);
    const tid=`t${Date.now()}`;
    setMsgs(p=>[...p,{id:tid,text,isSender:true,pending:true,delivered:false,seen:false,created_at:new Date().toISOString(),replyTo:replyTo?.id,replyToText:replyTo?.text}]);
    setReplyTo(null);
    try{
      let pk=active.public_key;
      if(!pk){ const d=await api("GET",`/users/${active.user_id}/public-key`,null,tok.current.access); pk=d.public_key; setActive(a=>({...a,public_key:pk})); }
      const payload=await encryptMsg(text,pk,user.public_key);
      if(wsRef.current?.readyState===WebSocket.OPEN){
        wsRef.current.send(JSON.stringify({event:"message.send",to:active.user_id,payload}));
        setMsgs(p=>p.map(m=>m.id===tid?{...m,pending:false}:m));
      } else {
        const d=await api("POST","/messages",{to:active.user_id,payload},tok.current.access);
        setMsgs(p=>p.map(m=>m.id===tid?{...d,text,isSender:true,seen:false}:m));
      }
      loadConvos();
    }catch{ setMsgs(p=>p.filter(m=>m.id!==tid)); if(!override) setDraft(text); }
    setSending(false);
  };

  const enterApp=(at,rt,u,pk)=>{
    tok.current={access:at,refresh:rt}; privKey.current=pk;
    SS.save(rt,u); setUser(u); setScreen("app");
  };

  const doRegister=async()=>{
    setAuthBusy(true); setAuthErr("");
    try{
      const salt=genSalt(); const kp=await genRSAKeyPair();
      const wk=await deriveWrapKey(fields.password,salt);
      const [pubB64,wrappedB64]=await Promise.all([exportPubKey(kp.publicKey),wrapPrivKey(kp.privateKey,wk)]);
      const data=await api("POST","/auth/register",{
        username:fields.username.toLowerCase(),display_name:fields.display_name||fields.username,
        password:fields.password,public_key:pubB64,wrapped_private_key:wrappedB64,pbkdf2_salt:b64enc(salt),
      });
      enterApp(data.access_token,data.refresh_token,data.user,kp.privateKey);
    }catch(e){ setAuthErr(e.message); }
    setAuthBusy(false);
  };

  const doLogin=async()=>{
    setAuthBusy(true); setAuthErr("");
    try{
      const data=await api("POST","/auth/login",{username:fields.username.toLowerCase(),password:fields.password});
      const wk=await deriveWrapKey(fields.password,b64dec(data.user.pbkdf2_salt));
      const pk=await unwrapPrivKey(data.user.wrapped_private_key,wk);
      enterApp(data.access_token,data.refresh_token,data.user,pk);
    }catch(e){ setAuthErr(e.message); }
    setAuthBusy(false);
  };

  const doUnlock=async password=>{
    setAuthBusy(true); setAuthErr("");
    const saved=SS.load();
    try{
      const data=await api("POST","/auth/refresh",{refresh_token:saved.refresh});
      const profile=await api("GET","/auth/me",null,data.access_token);
      const wk=await deriveWrapKey(password,b64dec(profile.pbkdf2_salt));
      const pk=await unwrapPrivKey(profile.wrapped_private_key,wk);
      tok.current={access:data.access_token,refresh:saved.refresh};
      privKey.current=pk; SS.save(saved.refresh,profile); setUser(profile); setScreen("app");
    }catch(e){
      const m=(e.message||"").toLowerCase();
      if(m.includes("401")||m.includes("expired")||m.includes("revoked")){
        SS.clear(); setScreen("auth"); setAuthErr("Session expired. Please sign in again.");
      } else { setAuthErr("Wrong password. Try again."); }
    }
    setAuthBusy(false);
  };

  const doLogout=async()=>{
    try{ await api("POST","/auth/logout",{refresh_token:tok.current.refresh},tok.current.access); }catch{}
    wsRef.current?.close(); tok.current={access:null,refresh:null}; privKey.current=null;
    SS.clear(); setUser(null); setConvos([]); setMsgs([]); setActive(null); setScreen("auth");
  };

  const saved=SS.load();
  return (
    <>
      <style>{CSS}</style>
      {screen==="unlock"&&<UnlockPage savedUser={saved?.user} onUnlock={doUnlock}
        onSwitch={()=>{SS.clear();setAuthErr("");setScreen("auth");}} err={authErr} busy={authBusy}/>}
      {screen==="auth"&&<AuthPage tab={authTab} setTab={setAuthTab} fields={fields} setFields={setFields}
        err={authErr} busy={authBusy} onLogin={doLogin} onRegister={doRegister} serverReady={serverReady}/>}
      {screen==="app"&&<AppShell
        user={user} convos={convos} active={active} msgs={msgs}
        loadingMsgs={loadingMsgs} draft={draft} setDraft={setDraft} sending={sending}
        searchQ={searchQ} setSearchQ={setSearchQ} searchRes={searchRes}
        wsOnline={wsOnline} onlineUsers={onlineUsers} lastSeenMap={lastSeenMap}
        theme={theme} onTheme={onTheme} onOpenConvo={openConvo} onSend={sendMsg}
        onLogout={doLogout} bottomRef={bottomRef} inputRef={inputRef}
        status={status} onSaveStatus={onSaveStatus} unreadMap={unreadMap}
        soundOn={soundOn} setSoundOn={setSoundOn} pushOn={pushOn} setPushOn={setPushOn}
        photo={photo} onPhotoChange={onPhotoChange}
        onLoadMore={onLoadMore} hasMore={hasMore} typingUsers={typingUsers} onTyping={onTyping}
        pinnedContacts={pinnedContacts} onTogglePin={onTogglePin}
        mutedConvos={mutedConvos} onToggleMute={onToggleMute}
        reactions={reactions} onReact={onReact} onDeleteMsg={onDeleteMsg}
        onReply={onReply} replyTo={replyTo} setReplyTo={setReplyTo}
        msgSearch={msgSearch} setMsgSearch={setMsgSearch}
        showMsgSearch={showMsgSearch} setShowMsgSearch={setShowMsgSearch}
      />}
    </>
  );
}

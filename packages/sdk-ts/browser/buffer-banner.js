(function(){ if (globalThis.Buffer) return;
  const dec = (s) => { s = s.replace(/[^A-Za-z0-9+/]/g, ""); while (s.length % 4) s += "="; const bin = atob(s);
    const u = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u; };
  const encB64 = (u) => { let s=""; for (let i=0;i<u.length;i++) s+=String.fromCharCode(u[i]); return btoa(s); };
  globalThis.Buffer = { from(x, enc){ let u;
    if (typeof x === "string") u = enc === "base64" ? dec(x) : new TextEncoder().encode(x);
    else u = x instanceof Uint8Array ? x : new Uint8Array(x);
    u.toString = (e) => e === "base64" ? encB64(u) : new TextDecoder().decode(u); return u; } };
})();

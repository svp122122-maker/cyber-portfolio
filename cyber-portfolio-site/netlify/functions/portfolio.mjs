import { getStore } from "@netlify/blobs";
import { timingSafeEqual, createHash } from "node:crypto";

export const config = { path: "/api/portfolio" };

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const sha = (s) => createHash("sha256").update(String(s)).digest();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MAX_BYTES = 400_000;

function cleanUrl(u) {
  if (typeof u !== "string" || !u) return "";
  try {
    const x = new URL(u);
    return x.protocol === "http:" || x.protocol === "https:" ? x.href : "";
  } catch {
    return "";
  }
}
const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");

function sanitize(d) {
  if (!d || typeof d !== "object") return null;
  if (!Array.isArray(d.sections) || !Array.isArray(d.items)) return null;
  if (d.sections.length > 80 || d.items.length > 3000) return null;
  const types = ["work", "cert", "link"];
  const sections = d.sections
    .filter((s) => s && typeof s.id === "string" && typeof s.title === "string")
    .map((s) => ({ id: str(s.id, 40), title: str(s.title, 80), desc: str(s.desc, 300) }));
  const items = d.items
    .filter((i) => i && typeof i.id === "string" && typeof i.sec === "string" && types.includes(i.type))
    .map((i) => ({
      id: str(i.id, 40), sec: str(i.sec, 40), type: i.type,
      title: str(i.title, 200), course: str(i.course, 160),
      url: cleanUrl(i.url), date: str(i.date, 10), note: str(i.note, 500),
    }));
  const p = d.profile && typeof d.profile === "object" ? d.profile : {};
  return { v: 1, profile: { name: str(p.name, 80), role: str(p.role, 120) }, sections, items };
}

export default async (req) => {
  const store = getStore("portfolio");

  if (req.method === "GET") {
    const data = await store.get("main", { type: "json" });
    return json(data ?? null);
  }

  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const secret = (globalThis.Netlify?.env?.get("EDIT_PASSWORD") ?? process.env.EDIT_PASSWORD) || "";
  if (secret.length < 8) return json({ error: "not_configured" }, 503);

  let body;
  try {
    const text = await req.text();
    if (text.length > MAX_BYTES) return json({ error: "too_large" }, 413);
    body = JSON.parse(text);
  } catch {
    return json({ error: "bad_request" }, 400);
  }

  const ok = timingSafeEqual(sha(body?.password ?? ""), sha(secret));
  if (!ok) {
    await sleep(800);
    return json({ error: "unauthorized" }, 401);
  }
  if (body.verify) return json({ ok: true });

  const clean = sanitize(body.data);
  if (!clean) return json({ error: "bad_data" }, 400);
  await store.setJSON("main", clean);
  return json({ ok: true });
};

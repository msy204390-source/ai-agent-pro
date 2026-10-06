import express from "express";
import cors from "cors";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import "dotenv/config";
import OpenAI from "openai";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const IS_PROD =
  process.env.NODE_ENV === "production";

const DATA_DIR =
  process.env.DATA_DIR ||
  path.join(__dirname, "data");

const DB_FILE =
  path.join(DATA_DIR, "db.json");

fs.mkdirSync(DATA_DIR, {
  recursive: true
});

/* =========================
   APP
========================= */

const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");

if (process.env.APP_URL) {
  app.use(
    cors({
      origin: process.env.APP_URL,
      credentials: true
    })
  );
}

app.use(
  express.json({
    limit: "150kb"
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: "100kb"
  })
);

/* =========================
   PLANS
========================= */

const PLANS = {
  starter: {
    name: "Starter",
    price: 29,
    days: 30,
    monthlyMessages: 250
  },

  business: {
    name: "Business",
    price: 79,
    days: 30,
    monthlyMessages: 1200
  },

  pro: {
    name: "Pro",
    price: 149,
    days: 30,
    monthlyMessages: 4000
  }
};

/* =========================
   DATABASE
========================= */

const defaultDb = {
  users: [],
  sessions: [],
  payments: [],
  usage: [],
  knowledge: [],
  settings: {}
};

function loadDb() {
  try {
    const raw = JSON.parse(
      fs.readFileSync(DB_FILE, "utf8")
    );

    return {
      users: Array.isArray(raw.users)
        ? raw.users
        : [],

      sessions: Array.isArray(raw.sessions)
        ? raw.sessions
        : [],

      payments: Array.isArray(raw.payments)
        ? raw.payments
        : [],

      usage: Array.isArray(raw.usage)
        ? raw.usage
        : [],

      knowledge: Array.isArray(raw.knowledge)
        ? raw.knowledge
        : [],

      settings:
        raw.settings &&
        typeof raw.settings === "object"
          ? raw.settings
          : {}
    };
  } catch {
    return structuredClone(defaultDb);
  }
}

let db = loadDb();

function saveDb() {
  const tmp =
    DB_FILE + ".tmp";

  fs.writeFileSync(
    tmp,
    JSON.stringify(
      db,
      null,
      2
    ),
    "utf8"
  );

  fs.renameSync(
    tmp,
    DB_FILE
  );
}

/* =========================
   HELPERS
========================= */

function id(prefix = "id") {
  return (
    prefix +
    "_" +
    crypto
      .randomBytes(9)
      .toString("hex")
  );
}

function now() {
  return new Date();
}

function iso(d) {
  return new Date(d).toISOString();
}

function normalizeEmail(v) {
  return String(v || "")
    .trim()
    .toLowerCase();
}

/* =========================
   PASSWORDS
========================= */

function hashPassword(
  password,
  salt = crypto
    .randomBytes(16)
    .toString("hex")
) {
  const hash =
    crypto
      .scryptSync(
        password,
        salt,
        64
      )
      .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  stored
) {
  try {
    const parts =
      String(stored || "").split(":");

    const salt = parts[0];
    const hash = parts[1];

    if (!salt || !hash) {
      return false;
    }

    const actual =
      crypto
        .scryptSync(
          password,
          salt,
          64
        )
        .toString("hex");

    const a =
      Buffer.from(
        actual,
        "hex"
      );

    const b =
      Buffer.from(
        hash,
        "hex"
      );

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      a,
      b
    );
  } catch {
    return false;
  }
}

/* =========================
   COOKIES
========================= */

function cookie(
  name,
  value,
  maxAgeSeconds
) {
  return `${name}=${encodeURIComponent(
    value
  )}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${
    IS_PROD
      ? "; Secure"
      : ""
  }`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${
    IS_PROD
      ? "; Secure"
      : ""
  }`;
}

/* =========================
   SESSIONS
========================= */

function createSession(userId) {
  const token =
    crypto
      .randomBytes(32)
      .toString("base64url");

  const expiresAt =
    Date.now() +
    Number(
      process.env.SESSION_DAYS || 14
    ) *
      86400000;

  db.sessions =
    db.sessions.filter(
      s =>
        s &&
        new Date(
          s.expiresAt
        ).getTime() >
          Date.now()
    );

  db.sessions.push({
    token,
    userId,
    expiresAt:
      new Date(
        expiresAt
      ).toISOString()
  });

  saveDb();

  return {
    token,
    expiresAt
  };
}

function getUser(req) {
  const raw =
    req.headers.cookie
      ?.split(";")
      .map(x => x.trim())
      .find(
        x =>
          x.startsWith(
            "session="
          )
      );

  if (!raw) {
    return null;
  }

  const token =
    decodeURIComponent(
      raw.slice(8)
    );

  const session =
    db.sessions.find(
      s =>
        s.token === token &&
        new Date(
          s.expiresAt
        ).getTime() >
          Date.now()
    );

  if (!session) {
    return null;
  }

  return (
    db.users.find(
      u =>
        u.id ===
        session.userId
    ) || null
  );
}

function requireAuth(
  req,
  res,
  next
) {
  const user =
    getUser(req);

  if (!user) {
    return res
      .status(401)
      .json({
        error:
          "يجب تسجيل الدخول أولاً"
      });
  }

  req.user = user;

  next();
}

/* =========================
   PLANS / USAGE
========================= */

function activePlan(user) {
  if (
    !user?.plan ||
    !user.planExpiresAt
  ) {
    return null;
  }

  if (
    new Date(
      user.planExpiresAt
    ).getTime() <=
    Date.now()
  ) {
    return null;
  }

  return PLANS[user.plan]
    ? user.plan
    : null;
}

function usageKey(userId) {
  const d =
    new Date();

  return `${userId}:${d.getUTCFullYear()}-${String(
    d.getUTCMonth() + 1
  ).padStart(2, "0")}`;
}

function usageCount(userId) {
  const key =
    usageKey(userId);

  return (
    db.usage.find(
      x =>
        x.key === key
    )?.messages || 0
  );
}

function addUsage(userId) {
  const key =
    usageKey(userId);

  let row =
    db.usage.find(
      x =>
        x.key === key
    );

  if (!row) {
    row = {
      key,
      userId,
      messages: 0
    };

    db.usage.push(row);
  }

  row.messages += 1;

  saveDb();
}

function publicUser(user) {
  const plan =
    activePlan(user);

  return {
    id: user.id,
    email: user.email,
    name: user.name || "",
    company: user.company || "",
    industry: user.industry || "",
    tone:
      user.tone ||
      "ودود واحترافي",

    plan,

    planExpiresAt:
      user.planExpiresAt ||
      null,

    usage:
      usageCount(
        user.id
      ),

    limit: plan
      ? PLANS[
          plan
        ].monthlyMessages
      : 0,

    isAdmin:
      !!user.isAdmin,

    createdAt:
      user.createdAt
  };
}

/* =========================
   ADMIN
========================= */

function admin(
  req,
  res,
  next
) {
  if (
    !req.user?.isAdmin
  ) {
    return res
      .status(403)
      .json({
        error:
          "غير مصرح"
      });
  }

  next();
}

/* =========================
   KNOWLEDGE BASE
========================= */

function getKnowledge(userId) {
  let row =
    db.knowledge.find(
      x =>
        x.userId ===
        userId
    );

  if (!row) {
    row = {
      userId,

      businessInfo: "",
      products: "",
      prices: "",
      faq: "",
      shipping: "",
      returns: "",
      contact: "",
      policies: "",

      updatedAt:
        iso(now())
    };

    db.knowledge.push(
      row
    );

    saveDb();
  }

  return row;
}

function publicKnowledge(userId) {
  const k =
    getKnowledge(
      userId
    );

  return {
    businessInfo:
      k.businessInfo || "",

    products:
      k.products || "",

    prices:
      k.prices || "",

    faq:
      k.faq || "",

    shipping:
      k.shipping || "",

    returns:
      k.returns || "",

    contact:
      k.contact || "",

    policies:
      k.policies || "",

    updatedAt:
      k.updatedAt || null
  };
}

function knowledgeForAI(userId) {
  const k =
    getKnowledge(
      userId
    );

  return `
معلومات الشركة الأساسية:
${
  k.businessInfo ||
  "لا توجد معلومات مدخلة."
}

المنتجات والخدمات:
${
  k.products ||
  "لا توجد معلومات مدخلة."
}

الأسعار:
${
  k.prices ||
  "لا توجد أسعار مدخلة."
}

الأسئلة الشائعة:
${
  k.faq ||
  "لا توجد أسئلة شائعة مدخلة."
}

الشحن والتوصيل:
${
  k.shipping ||
  "لا توجد معلومات عن الشحن."
}

الاستبدال والاسترجاع:
${
  k.returns ||
  "لا توجد معلومات عن الاستبدال والاسترجاع."
}

معلومات التواصل:
${
  k.contact ||
  "لا توجد معلومات تواصل مدخلة."
}

سياسات الشركة:
${
  k.policies ||
  "لا توجد سياسات مدخلة."
}
`;
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

app.use(
  express.static(__dirname)
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
    return {
      ...structuredClone(defaultDb),
      ...JSON.parse(
        fs.readFileSync(
          DB_FILE,
          "utf8"
        )
      )
    };
  } catch {
    return structuredClone(
      defaultDb
    );
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
    )
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
  const [
    salt,
    hash
  ] = String(
    stored || ""
  ).split(":");

  if (
    !salt ||
    !hash
  ) {
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

  return crypto.timingSafeEqual(
    Buffer.from(
      actual,
      "hex"
    ),
    Buffer.from(
      hash,
      "hex"
    )
  );
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

function createSession(
  userId
) {
  const token =
    crypto
      .randomBytes(32)
      .toString("base64url");

  const expiresAt =
    Date.now() +
    Number(
      process.env.SESSION_DAYS ||
        14
    ) *
      86400000;

  db.sessions =
    db.sessions.filter(
      s =>
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
      .map(x =>
        x.trim()
      )
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
        s.token ===
          token &&
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

function usageKey(
  userId
) {
  const d =
    new Date();

  return `${userId}:${d.getUTCFullYear()}-${String(
    d.getUTCMonth() + 1
  ).padStart(2, "0")}`;
}

function usageCount(
  userId
) {
  const key =
    usageKey(userId);

  return (
    db.usage.find(
      x =>
        x.key === key
    )?.messages || 0
  );
}

function addUsage(
  userId
) {
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

function publicUser(
  user
) {
  const plan =
    activePlan(user);

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    company: user.company,
    industry: user.industry,
    tone: user.tone,

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

function getKnowledge(
  userId
) {
  let row =
    db.knowledge.find(
      x =>
        x.userId ===
        userId
    );

  if (!row) {
    row = {
      userId,

      businessInfo:
        "",

      products:
        "",

      prices:
        "",

      faq:
        "",

      shipping:
        "",

      returns:
        "",

      contact:
        "",

      policies:
        "",

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

function publicKnowledge(
  userId
) {
  const k =
    getKnowledge(
      userId
    );

  return {
    businessInfo:
      k.businessInfo ||
      "",

    products:
      k.products ||
      "",

    prices:
      k.prices ||
      "",

    faq:
      k.faq ||
      "",

    shipping:
      k.shipping ||
      "",

    returns:
      k.returns ||
      "",

    contact:
      k.contact ||
      "",

    policies:
      k.policies ||
      "",

    updatedAt:
      k.updatedAt ||
      null
  };
}

function knowledgeForAI(
  userId
) {
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
}

app.get(
  "/api/knowledge",
  requireAuth,
  (req, res) => {
    res.json({
      knowledge:
        publicKnowledge(
          req.user.id
        )
    });
  }
);

app.put(
  "/api/knowledge",
  requireAuth,
  (req, res) => {
    const k =
      getKnowledge(
        req.user.id
      );

    const clean = (
      value,
      max = 8000
    ) =>
      String(
        value || ""
      )
        .trim()
        .slice(0, max);

    k.businessInfo =
      clean(
        req.body
          ?.businessInfo
      );

    k.products =
      clean(
        req.body
          ?.products
      );

    k.prices =
      clean(
        req.body
          ?.prices
      );

    k.faq =
      clean(
        req.body?.faq
      );

    k.shipping =
      clean(
        req.body
          ?.shipping
      );

    k.returns =
      clean(
        req.body
          ?.returns
      );

    k.contact =
      clean(
        req.body
          ?.contact
      );

    k.policies =
      clean(
        req.body
          ?.policies
      );

    k.updatedAt =
      iso(now());

    saveDb();

    res.json({
      ok: true,

      knowledge:
        publicKnowledge(
          req.user.id
        )
    });
  }
);

/* =========================
   ADMIN SEED
========================= */

function seedAdmin() {
  const email =
    normalizeEmail(
      process.env
        .ADMIN_EMAIL
    );

  const password =
    process.env
      .ADMIN_PASSWORD;

  if (
    !email ||
    !password
  ) {
    return;
  }

  let user =
    db.users.find(
      u =>
        u.email ===
        email
    );

  if (!user) {
    user = {
      id: "admin",

      email,

      passwordHash:
        hashPassword(
          password
        ),

      name: "Admin",

      company:
        "AI Agent Pro",

      industry:
        "AI",

      tone:
        "احترافي",

      plan: "pro",

      planExpiresAt:
        "2099-01-01T00:00:00.000Z",

      isAdmin:
        true,

      createdAt:
        iso(now())
    };

    db.users.push(
      user
    );
  } else {
    user.isAdmin =
      true;

    user.passwordHash =
      hashPassword(
        password
      );

    user.plan =
      "pro";

    user.planExpiresAt =
      "2099-01-01T00:00:00.000Z";
  }

  saveDb();
}

seedAdmin();

/* =========================
   OPENAI
========================= */

const client =
  process.env.OPENAI_API_KEY
    ? new OpenAI({
        apiKey:
          process.env
            .OPENAI_API_KEY
      })
    : null;

/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  (_req, res) =>
    res.json({
      ok: true,

      aiConfigured:
        !!client,

      frontend:
        fs.existsSync(
          path.join(
            __dirname,
            "index.html"
          )
        ),

      imageAccess:
        false,

      knowledgeBase:
        true
    })
);

/* =========================
   SIGNUP
========================= */

app.post(
  "/api/signup",
  (req, res) => {
    const email =
      normalizeEmail(
        req.body?.email
      );

    const password =
      String(
        req.body?.password ||
          ""
      );

    const name =
      String(
        req.body?.name ||
          ""
      ).trim();

    if (
      !/^\S+@\S+\.\S+$/.test(
        email
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "أدخل بريد إلكتروني صحيح"
        });
    }

    if (
      password.length <
      8
    ) {
      return res
        .status(400)
        .json({
          error:
            "كلمة المرور يجب أن تكون 8 أحرف على الأقل"
        });
    }

    if (
      db.users.some(
        u =>
          u.email ===
          email
      )
    ) {
      return res
        .status(409)
        .json({
          error:
            "هذا البريد مسجل مسبقاً"
        });
    }

    const user = {
      id: id("usr"),

      email,

      passwordHash:
        hashPassword(
          password
        ),

      name:
        name ||
        "عميل",

      company:
        "",

      industry:
        "",

      tone:
        "ودود واحترافي",

      plan:
        null,

      planExpiresAt:
        null,

      isAdmin:
        false,

      createdAt:
        iso(now())
    };

    db.users.push(
      user
    );

    getKnowledge(
      user.id
    );

    saveDb();

    const s =
      createSession(
        user.id
      );

    res.setHeader(
      "Set-Cookie",
      cookie(
        "session",
        s.token,
        Number(
          process.env
            .SESSION_DAYS ||
            14
        ) * 86400
      )
    );

    res.json({
      user:
        publicUser(
          user
        )
    });
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  (req, res) => {
    const email =
      normalizeEmail(
        req.body?.email
      );

    const password =
      String(
        req.body?.password ||
          ""
      );

    const user =
      db.users.find(
        u =>
          u.email ===
          email
      );

    if (
      !user ||
      !verifyPassword(
        password,
        user.passwordHash
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            "البريد أو كلمة المرور غير صحيحة"
        });
    }

    const s =
      createSession(
        user.id
      );

    res.setHeader(
      "Set-Cookie",
      cookie(
        "session",
        s.token,
        Number(
          process.env
            .SESSION_DAYS ||
            14
        ) * 86400
      )
    );

    res.json({
      user:
        publicUser(
          user
        )
    });
  }
);

/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  (req, res) => {
    const raw =
      req.headers.cookie
        ?.split(";")
        .map(x =>
          x.trim()
        )
        .find(
          x =>
            x.startsWith(
              "session="
            )
        );

    if (raw) {
      db.sessions =
        db.sessions.filter(
          s =>
            s.token !==
            decodeURIComponent(
              raw.slice(8)
            )
        );
    }

    saveDb();

    res.setHeader(
      "Set-Cookie",
      clearCookie(
        "session"
      )
    );

    res.json({
      ok: true
    });
  }
);

/* =========================
   ME
========================= */

app.get(
  "/api/me",
  (req, res) => {
    const u =
      getUser(req);

    res.json({
      user: u
        ? publicUser(u)
        : null
    });
  }
);

/* =========================
   PROFILE
========================= */

app.put(
  "/api/profile",
  requireAuth,
  (req, res) => {
    const u =
      req.user;

    u.name =
      String(
        req.body?.name ||
          u.name
      )
        .trim()
        .slice(
          0,
          100
        );

    u.company =
      String(
        req.body?.company ||
          ""
      )
        .trim()
        .slice(
          0,
          120
        );

    u.industry =
      String(
        req.body?.industry ||
          ""
      )
        .trim()
        .slice(
          0,
          120
        );

    u.tone =
      String(
        req.body?.tone ||
          "ودود واحترافي"
      )
        .trim()
        .slice(
          0,
          80
        );

    saveDb();

    res.json({
      user:
        publicUser(
          u
        )
    });
  }
);

/* =========================
   AI INSTRUCTIONS
========================= */

function buildInstructions(
  user
) {
  const plan =
    activePlan(
      user
    );

  const profile =
    `اسم العميل: ${
      user.name ||
      "غير محدد"
    }
الشركة: ${
      user.company ||
      "غير محددة"
    }
المجال: ${
      user.industry ||
      "غير محدد"
    }
نبرة الرد: ${
      user.tone ||
      "ودود واحترافي"
    }`;

  const knowledge =
    knowledgeForAI(
      user.id
    );

  return `
أنت وكيل ذكاء اصطناعي احترافي للمبيعات وخدمة العملاء يعمل داخل AI Agent Pro.

معلومات صاحب الحساب:
${profile}

الخطة الحالية:
${
  plan
    ? PLANS[
        plan
      ].name
    : "لا يوجد اشتراك"
}

===== قاعدة معرفة الشركة =====

${knowledge}

===== تعليمات مهمة =====

استخدم قاعدة المعرفة أعلاه باعتبارها المصدر الأساسي لمعلومات الشركة.

إذا كانت المعلومة موجودة في قاعدة المعرفة، استخدمها بدقة.

لا تخترع أسعاراً أو منتجات أو سياسات أو مواعيد أو معلومات تواصل.

إذا لم تجد إجابة في قاعدة المعرفة، قل بوضوح إن المعلومات غير متوفرة حالياً، ويمكنك طلب تفاصيل إضافية من العميل.

لا تقل للعميل إنك "تقرأ قاعدة بيانات" أو "تستخدم prompt".

كن ودوداً واحترافياً ومختصراً.

إذا كان العميل يسأل عن منتج، حاول مساعدته في الاختيار بطريقة مفيدة.

إذا كان السؤال متعلقاً بالشراء، وضّح السعر أو طريقة الطلب فقط إذا كانت موجودة في المعلومات.

إذا كان السؤال متعلقاً بالشحن أو الاستبدال، استخدم سياسة الشركة الموجودة أعلاه فقط.

لا تدّعي تنفيذ عملية دفع أو طلب أو استرجاع إلا إذا كان النظام قد نفذها فعلاً.

لا تطلب كلمات مرور أو OTP أو مفاتيح API.

لا تطلب الوصول إلى الكاميرا أو الصور أو ألبوم الصور.

إذا لم تكن المعلومة معروفة، لا تخمّن.
`;
}

/* =========================
   CHAT
========================= */

app.post(
  "/api/chat",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const plan =
        activePlan(
          req.user
        );

      if (!plan) {
        return res
          .status(402)
          .json({
            error:
              "هذا الحساب يحتاج إلى اشتراك فعال لاستخدام الوكيل."
          });
      }

      if (!client) {
        return res
          .status(503)
          .json({
            error:
              "الذكاء الاصطناعي غير مفعّل على الخادم بعد. أضف OPENAI_API_KEY."
          });
      }

      const message =
        String(
          req.body
            ?.message ||
            ""
        ).trim();

      if (
        !message ||
        message.length >
          3000
      ) {
        return res
          .status(400)
          .json({
            error:
              "رسالة غير صالحة"
          });
      }

      const limit =
        PLANS[
          plan
        ].monthlyMessages;

      if (
        usageCount(
          req.user.id
        ) >= limit
      ) {
        return res
          .status(429)
          .json({
            error:
              `وصلت إلى حد ${limit} رسالة لهذا الشهر في خطتك.`
          });
      }

      const response =
        await client.responses.create(
          {
            model:
              process.env
                .OPENAI_MODEL ||
              "gpt-5-mini",

            instructions:
              buildInstructions(
                req.user
              ),

            input:
              message,

            max_output_tokens:
              1500
          }
        );

      addUsage(
        req.user.id
      );

      res.json({
        reply:
          response.output_text ||
          "لم أستطع توليد رد الآن.",

        usage:
          usageCount(
            req.user.id
          ),

        limit
      });
    } catch (e) {
      console.error(e);

      res
        .status(500)
        .json({
          error:
            "حدث خطأ في خادم الذكاء الاصطناعي."
        });
    }
  }
);

/* =========================
   KAZAWALLET
========================= */

async function createKazaLink({
  amount,
  currency,
  ref,
  redirectUrl
}) {
  if (
    !process.env
      .KAZA_API_KEY ||
    !process.env
      .KAZA_MERCHANT_EMAIL
  ) {
    return null;
  }

  const r =
    await fetch(
      `${
        process.env
          .KAZA_API_BASE ||
        "https://outdoor.kasroad.com/wallet"
      }/createPaymentLink`,
      {
        method:
          "POST",

        headers: {
          "x-api-key":
            process.env
              .KAZA_API_KEY,

          "Content-Type":
            "application/json"
        },

        body:
          JSON.stringify({
            amount:
              String(
                amount
              ),

            currency,

            email:
              process.env
                .KAZA_MERCHANT_EMAIL,

            ref,

            redirectUrl
          })
      }
    );

  const data =
    await r.json();

  const link =
    data.paymentLink ||
    data.link ||
    data.url ||
    data.data
      ?.paymentLink ||
    data.data?.link;

  if (
    !r.ok ||
    !link
  ) {
    throw new Error(
      data?.error ||
        "Kazawallet API error"
    );
  }

  return link;
}

app.post(
  "/api/checkout",
  requireAuth,
  async (
    req,
    res
  ) => {
    const planId =
      String(
        req.body?.plan ||
          "starter"
      );

    const plan =
      PLANS[planId];

    if (!plan) {
      return res
        .status(400)
        .json({
          error:
            "الخطة غير موجودة"
        });
    }

    const ref =
      `${req.user.id}:${planId}:${Date.now()}`;

    const base =
      process.env.APP_URL ||
      `${req.protocol}://${req.get(
        "host"
      )}`;

    let url =
      null;

    try {
      url =
        await createKazaLink(
          {
            amount:
              plan.price,

            currency:
              "USD",

            ref,

            redirectUrl:
              `${base}/?payment=success&ref=${encodeURIComponent(
                ref
              )}`
          }
        );
    } catch (e) {
      console.error(e);
    }

    if (
      !url &&
      planId ===
        "starter"
    ) {
      url =
        process.env
          .STARTER_PAYMENT_LINK ||
        null;
    }

    const payment = {
      id: id("pay"),

      userId:
        req.user.id,

      plan:
        planId,

      amount:
        plan.price,

      currency:
        "USD",

      ref,

      status:
        "pending",

      url,

      createdAt:
        iso(now())
    };

    db.payments.push(
      payment
    );

    saveDb();

    if (!url) {
      return res
        .status(503)
        .json({
          error:
            "الدفع الآلي يحتاج تفعيل حساب Kazawallet Merchant وبيانات API على الخادم."
        });
    }

    res.json({
      url,

      paymentId:
        payment.id,

      mode:
        process.env
          .KAZA_API_KEY
          ? "api"
          : "manual"
    });
  }
);

/* =========================
   KAZAWALLET WEBHOOK
========================= */

function verifyKazaWebhook(
  payload
) {
  if (
    !process.env
      .KAZA_API_KEY ||
    !process.env
      .KAZA_API_SECRET
  ) {
    return false;
  }

  const amount =
    String(
      payload.amount ??
        ""
    );

  const orderId =
    String(
      payload.order_id ??
        ""
    );

  const secretString =
    `${amount}:::${orderId}:::${process.env.KAZA_API_KEY}`;

  const sha =
    crypto
      .createHash(
        "sha256"
      )
      .update(
        secretString
      )
      .digest();

  const digest =
    crypto
      .createHmac(
        "sha512",
        process.env
          .KAZA_API_SECRET
      )
      .update(sha)
      .digest("base64");

  const a =
    Buffer.from(
      digest
    );

  const b =
    Buffer.from(
      String(
        payload.secret ||
          ""
      )
    );

  return (
    a.length ===
      b.length &&
    crypto.timingSafeEqual(
      a,
      b
    )
  );
}

app.post(
  "/api/kazawallet/webhook",
  (
    req,
    res
  ) => {
    const p =
      req.body || {};

    if (
      !verifyKazaWebhook(
        p
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            "Invalid webhook signature"
        });
    }

    const payment =
      db.payments.find(
        x =>
          x.ref ===
          String(
            p.ref ||
              ""
          )
      );

    if (!payment) {
      return res
        .status(404)
        .json({
          error:
            "Payment reference not found"
        });
    }

    if (
      p.status ===
      "fulfilled"
    ) {
      payment.status =
        "paid";

      payment.orderId =
        String(
          p.order_id ||
            ""
        );

      payment.paidAt =
        iso(now());

      const user =
        db.users.find(
          u =>
            u.id ===
            payment.userId
        );

      if (user) {
        user.plan =
          payment.plan;

        user.planExpiresAt =
          iso(
            new Date(
              Date.now() +
                PLANS[
                  payment.plan
                ].days *
                  86400000
            )
          );
      }
    } else if (
      p.status ===
      "timed_out"
    ) {
      payment.status =
        "timed_out";
    }

    saveDb();

    res.json({
      ok: true
    });
  }
);

/* =========================
   ADMIN PAYMENTS
========================= */

app.get(
  "/api/payments",
  requireAuth,
  admin,
  (_req, res) =>
    res.json({
      payments:
        db.payments
          .slice()
          .reverse()
          .map(
            p => ({
              ...p
            })
          )
    })
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  requireAuth,
  admin,
  (_req, res) =>
    res.json({
      users:
        db.users.map(
          publicUser
        )
    })
);

/* =========================
   ADMIN ACTIVATE
========================= */

app.post(
  "/api/admin/activate",
  requireAuth,
  admin,
  (
    req,
    res
  ) => {
    const user =
      db.users.find(
        u =>
          u.id ===
          String(
            req.body
              ?.userId
          )
      );

    const plan =
      PLANS[
        String(
          req.body
            ?.plan
        )
      ];

    if (
      !user ||
      !plan
    ) {
      return res
        .status(400)
        .json({
          error:
            "بيانات غير صالحة"
        });
    }

    user.plan =
      String(
        req.body
          .plan
      );

    user.planExpiresAt =
      iso(
        new Date(
          Date.now() +
            plan.days *
              86400000
        )
      );

    saveDb();

    res.json({
      user:
        publicUser(
          user
        )
    });
  }
);

/* =========================
   CONFIG
========================= */

app.get(
  "/api/config",
  (_req, res) =>
    res.json({
      plans:
        PLANS,

      imageAccess:
        false,

      knowledgeBase:
        true,

      starterManual:
        !!process.env
          .STARTER_PAYMENT_LINK,

      automaticPayments:
        !!process.env
          .KAZA_API_KEY
    })
);

/* =========================
   API 404
========================= */

app.use(
  "/api",
  (
    _req,
    res
  ) =>
    res
      .status(404)
      .json({
        error:
          "Not found"
      })
);

/* =========================
   FRONTEND
========================= */

app.use(
  (
    _req,
    res
  ) => {
    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      ),
      err => {
        if (
          err &&
          !res.headersSent
        ) {
          res
            .status(500)
            .send(
              "Frontend missing: index.html"
            );
        }
      }
    );
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (
    err,
    _req,
    res,
    _next
  ) => {
    console.error(err);

    if (
      !res.headersSent
    ) {
      res
        .status(500)
        .json({
          error:
            "خطأ داخلي في الخادم"
        });
    }
  }
);

/* =========================
   START SERVER
========================= */

const port =
  Number(
    process.env.PORT ||
      3000
  );

app.listen(
  port,
  "0.0.0.0",
  () =>
    console.log(
      `AI Agent Pro running on port ${port}`
    )
);
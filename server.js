import express from "express";
import cors from "cors";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import "dotenv/config";
import OpenAI from "openai";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IS_PROD = process.env.NODE_ENV === "production";

const DATA_DIR =
  process.env.DATA_DIR ||
  path.join(__dirname, "data");

const DB_FILE =
  path.join(DATA_DIR, "db.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

/* =========================
   الخطط المدفوعة
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
   التجربة المجانية
========================= */

const FREE_TRIAL_MESSAGES = 20;

/* =========================
   قاعدة البيانات
========================= */

const defaultDb = {
  users: [],
  sessions: [],
  payments: [],
  usage: [],
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
    )
  );

  fs.renameSync(
    tmp,
    DB_FILE
  );
}

/* =========================
   أدوات عامة
========================= */

function id(prefix = "id") {
  return (
    prefix +
    "_" +
    crypto.randomBytes(9).toString("hex")
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
   كلمات المرور
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
  const [salt, hash] =
    String(stored || "")
      .split(":");

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

  return crypto.timingSafeEqual(
    Buffer.from(actual, "hex"),
    Buffer.from(hash, "hex")
  );
}

/* =========================
   الكوكيز
========================= */

function cookie(
  name,
  value,
  maxAgeSeconds
) {
  return (
    `${name}=${encodeURIComponent(value)}; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `SameSite=Lax; ` +
    `Max-Age=${maxAgeSeconds}` +
    `${IS_PROD ? "; Secure" : ""}`
  );
}

function clearCookie(name) {
  return (
    `${name}=; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `SameSite=Lax; ` +
    `Max-Age=0` +
    `${IS_PROD ? "; Secure" : ""}`
  );
}

/* =========================
   الجلسات
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
   التجربة المجانية
========================= */

function trialUsage(user) {
  return Number(
    user?.trialMessagesUsed || 0
  );
}

function hasFreeTrial(user) {
  if (!user) {
    return false;
  }

  return (
    trialUsage(user) <
    FREE_TRIAL_MESSAGES
  );
}

/* =========================
   الخطة المدفوعة الحالية
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

/* =========================
   الوصول الحالي
========================= */

function activeAccess(user) {
  const plan =
    activePlan(user);

  /*
    إذا عنده اشتراك مدفوع
    نستخدم الخطة المدفوعة.
  */

  if (plan) {
    return {
      type: "paid",
      plan,
      limit:
        PLANS[plan]
          .monthlyMessages,
      usage:
        usageCount(user.id)
    };
  }

  /*
    إذا ما عنده اشتراك،
    نعطيه الـ20 المجانية.
  */

  if (
    hasFreeTrial(user)
  ) {
    return {
      type: "trial",
      plan: null,
      limit:
        FREE_TRIAL_MESSAGES,
      usage:
        trialUsage(user)
    };
  }

  /*
    انتهت الـ20 ولا يوجد اشتراك.
  */

  return null;
}

/* =========================
   الاستخدام الشهري
   للخطط المدفوعة
========================= */

function usageKey(userId) {
  const d =
    new Date();

  return (
    `${userId}:` +
    `${d.getUTCFullYear()}-` +
    `${String(
      d.getUTCMonth() + 1
    ).padStart(2, "0")}`
  );
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

/* =========================
   استخدام الرسائل المجانية
========================= */

function addTrialUsage(user) {
  user.trialMessagesUsed =
    trialUsage(user) + 1;

  saveDb();
}

/* =========================
   بيانات المستخدم العامة
========================= */

function publicUser(user) {
  const plan =
    activePlan(user);

  const trial =
    !plan &&
    hasFreeTrial(user);

  let usage = 0;
  let limit = 0;
  let publicPlan = null;

  if (plan) {
    publicPlan = plan;

    usage =
      usageCount(
        user.id
      );

    limit =
      PLANS[plan]
        .monthlyMessages;

  } else if (trial) {
    publicPlan = "trial";

    usage =
      trialUsage(user);

    limit =
      FREE_TRIAL_MESSAGES;

  } else {
    publicPlan = null;

    usage =
      FREE_TRIAL_MESSAGES;

    limit = 0;
  }

  return {
    id: user.id,

    email:
      user.email,

    name:
      user.name,

    company:
      user.company,

    industry:
      user.industry,

    tone:
      user.tone,

    plan:
      publicPlan,

    planExpiresAt:
      user.planExpiresAt ||
      null,

    usage,

    limit,

    trialMessagesUsed:
      trialUsage(user),

    trialMessagesLimit:
      FREE_TRIAL_MESSAGES,

    isAdmin:
      !!user.isAdmin,

    createdAt:
      user.createdAt
  };
}

/* =========================
   الأدمن
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
   إنشاء حساب الأدمن
========================= */

function seedAdmin() {
  const email =
    normalizeEmail(
      process.env.ADMIN_EMAIL
    );

  const password =
    process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    return;
  }

  let user =
    db.users.find(
      u =>
        u.email === email
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

      plan:
        "pro",

      planExpiresAt:
        "2099-01-01T00:00:00.000Z",

      trialMessagesUsed:
        FREE_TRIAL_MESSAGES,

      trialGranted:
        true,

      isAdmin:
        true,

      createdAt:
        iso(now())
    };

    db.users.push(user);

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

/* =========================
   ترقية الحسابات القديمة
   وإعطاؤها الـ20 المجانية
========================= */

function migrateFreeTrials() {
  let changed =
    false;

  for (
    const user of db.users
  ) {
    /*
      الحسابات القديمة التي
      ليس لديها اشتراك تحصل
      على التجربة المجانية.
    */

    if (
      user.trialMessagesUsed ===
      undefined
    ) {
      user.trialMessagesUsed =
        0;

      changed =
        true;
    }

    if (
      user.trialGranted ===
      undefined
    ) {
      user.trialGranted =
        true;

      changed =
        true;
    }
  }

  if (changed) {
    saveDb();
  }
}

seedAdmin();
migrateFreeTrials();

/* =========================
   Express
========================= */

const app =
  express();

app.set(
  "trust proxy",
  1
);

app.disable(
  "x-powered-by"
);

if (
  process.env.APP_URL
) {
  app.use(
    cors({
      origin:
        process.env.APP_URL,

      credentials:
        true
    })
  );
}

app.use(
  express.json({
    limit:
      "100kb"
  })
);

app.use(
  express.urlencoded({
    extended:
      false,

    limit:
      "100kb"
  })
);

/* =========================
   الملفات
========================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/* =========================
   OpenAI
========================= */

const client =
  process.env.OPENAI_API_KEY
    ? new OpenAI({
        apiKey:
          process.env.OPENAI_API_KEY
      })
    : null;

/* =========================
   Health
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
            "public",
            "index.html"
          )
        ),

      imageAccess:
        false
    })
);

/* =========================
   إنشاء حساب
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
      id:
        id("usr"),

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

      /*
        لا يوجد اشتراك مدفوع.
        يبدأ الحساب بـ20 رسالة
        مجانية فقط.
      */

      plan:
        null,

      planExpiresAt:
        null,

      trialMessagesUsed:
        0,

      trialGranted:
        true,

      isAdmin:
        false,

      createdAt:
        iso(now())
    };

    db.users.push(
      user
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
        ) *
          86400
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
   تسجيل الدخول
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
        ) *
          86400
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
   تسجيل الخروج
========================= */

app.post(
  "/api/logout",
  (req, res) => {
    const raw =
      req.headers.cookie
        ?.split(";")
        .map(
          x => x.trim()
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
   المستخدم الحالي
========================= */

app.get(
  "/api/me",
  (req, res) => {
    const u =
      getUser(req);

    res.json({
      user:
        u
          ? publicUser(u)
          : null
    });
  }
);

/* =========================
   الملف الشخصي
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
        publicUser(u)
    });
  }
);

/* =========================
   تعليمات الذكاء الاصطناعي
========================= */

function buildInstructions(user) {
  const plan =
    activePlan(user);

  const currentPlan =
    plan
      ? PLANS[plan].name
      : hasFreeTrial(user)
      ? "التجربة المجانية"
      : "لا يوجد اشتراك";

  const profile =
    `اسم العميل: ${
      user.name ||
      "غير محدد"
    }\n` +

    `الشركة: ${
      user.company ||
      "غير محددة"
    }\n` +

    `المجال: ${
      user.industry ||
      "غير محدد"
    }\n` +

    `نبرة الرد: ${
      user.tone ||
      "ودود واحترافي"
    }`;

  return (
    `أنت وكيل ذكاء اصطناعي للمبيعات وخدمة العملاء يعمل داخل خدمة AI Agent Pro.\n` +

    `${profile}\n` +

    `خطة المستخدم الحالية: ${currentPlan}.\n` +

    `كن دقيقاً، مختصراً ومفيداً. ` +

    `لا تخترع أسعاراً أو سياسات أو عمليات لم ينفذها النظام. ` +

    `إذا لم تعرف معلومة فقل إنك تحتاج تفاصيل إضافية. ` +

    `لا تطلب أبداً صور المستخدم ولا تطلب الوصول إلى ألبوم الصور أو الكاميرا أو أي صلاحية على جهازه. ` +

    `لا تطلب كلمات مرور أو رموز OTP أو مفاتيح API.\n` +

    `إذا كان السؤال خارج نطاق نشاط الشركة، أجب بإيجاز ووجّه المستخدم للخدمة المناسبة.`
  );
}

/* =========================
   المحادثة مع AI
========================= */

app.post(
  "/api/chat",
  requireAuth,
  async (req, res) => {
    try {
      const access =
        activeAccess(
          req.user
        );

      /*
        لا يوجد اشتراك
        وانتهت الـ20 المجانية.
      */

      if (!access) {
        return res
          .status(402)
          .json({
            error:
              "انتهت رسائلك المجانية الـ20. اشترك بخطة مدفوعة لمتابعة استخدام الوكيل."
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
          req.body?.message ||
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

      /*
        التأكد من وجود رسائل
        متبقية.
      */

      if (
        access.usage >=
        access.limit
      ) {
        if (
          access.type ===
          "trial"
        ) {
          return res
            .status(402)
            .json({
              error:
                "انتهت رسائلك المجانية الـ20. اشترك بخطة مدفوعة لمتابعة استخدام الوكيل."
            });
        }

        return res
          .status(429)
          .json({
            error:
              `وصلت إلى حد ${access.limit} رسالة لهذا الشهر في خطتك.`
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

      /*
        تسجيل الرسالة
        بعد نجاح رد AI فقط.
      */

      if (
        access.type ===
        "trial"
      ) {
        addTrialUsage(
          req.user
        );
      } else {
        addUsage(
          req.user.id
        );
      }

      const newUsage =
        access.type ===
        "trial"
          ? trialUsage(
              req.user
            )
          : usageCount(
              req.user.id
            );

      res.json({
        reply:
          response.output_text ||
          "لم أستطع توليد رد الآن.",

        usage:
          newUsage,

        limit:
          access.limit,

        trial:
          access.type ===
          "trial",

        remaining:
          Math.max(
            0,
            access.limit -
              newUsage
          )
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
   Kazawallet
========================= */

async function createKazaLink({
  amount,
  currency,
  ref,
  redirectUrl
}) {
  if (
    !process.env.KAZA_API_KEY ||
    !process.env.KAZA_MERCHANT_EMAIL
  ) {
    return null;
  }

  const r =
    await fetch(
      `${
        process.env.KAZA_API_BASE ||
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

/* =========================
   الدفع
========================= */

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
      `${req.user.id}:` +
      `${planId}:` +
      `${Date.now()}`;

    const base =
      process.env.APP_URL ||
      `${req.protocol}://${req.get(
        "host"
      )}`;

    let url = null;

    try {
      url =
        await createKazaLink({
          amount:
            plan.price,

          currency:
            "USD",

          ref,

          redirectUrl:
            `${base}/?payment=success&ref=${encodeURIComponent(
              ref
            )}`
        });
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
      id:
        id("pay"),

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
   التحقق من Kazawallet
========================= */

function verifyKazaWebhook(
  payload
) {
  if (
    !process.env.KAZA_API_KEY ||
    !process.env.KAZA_API_SECRET
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
    `${amount}:::` +
    `${orderId}:::` +
    `${process.env.KAZA_API_KEY}`;

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
      .digest(
        "base64"
      );

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

/* =========================
   Webhook
========================= */

app.post(
  "/api/kazawallet/webhook",
  (
    req,
    res
  ) => {
    const p =
      req.body || {};

    if (
      !verifyKazaWebhook(p)
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
            p.ref || ""
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
   المدفوعات - أدمن
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
   المستخدمون - أدمن
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
   تفعيل خطة يدوياً - أدمن
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
            req.body?.userId
          )
      );

    const plan =
      PLANS[
        String(
          req.body?.plan
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
        req.body.plan
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
   إعدادات الواجهة
========================= */

app.get(
  "/api/config",
  (
    _req,
    res
  ) =>
    res.json({
      plans:
        PLANS,

      freeTrial: {
        enabled:
          true,

        messages:
          FREE_TRIAL_MESSAGES
      },

      imageAccess:
        false,

      starterManual:
        !!process.env
          .STARTER_PAYMENT_LINK,

      automaticPayments:
        !!process.env
          .KAZA_API_KEY
    })
);

/* =========================
   مسارات API غير موجودة
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
   الصفحة الرئيسية
========================= */

app.use(
  (
    _req,
    res
  ) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
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
              "Frontend missing: public/index.html"
            );
        }
      }
    );
  }
);

/* =========================
   معالج الأخطاء
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
   تشغيل السيرفر
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
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
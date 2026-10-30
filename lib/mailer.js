/**
 * Gui email cho khach dat ve.
 *
 * Hai che do:
 *   - SMTP  : khi SMTP_HOST duoc khai bao trong .env -> gui that
 *   - DEV   : khi khong co SMTP_HOST -> ghi email ra file .eml trong mail-dev/
 *             (mo bang Outlook/Thunderbird de xem). Khong gui ra ngoai.
 *
 * Nguyen tac:
 *   - Gui BAT DONG BO, goi sau khi transaction da commit -> SMTP cham khong
 *     lam cham API, va khong gui email cho ve bi rollback.
 *   - Log KHONG chua email day du (chi che bot) de khong ro ri PII ra log file.
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { maskEmail } = require('./crypto');

const DEV_DIR = path.resolve(process.cwd(), process.env.MAIL_DEV_DIR || 'mail-dev');
const MAIL_FROM = process.env.MAIL_FROM || '"SkyBooking" <no-reply@skybooking.local>';

let transporter = null;
let mode = null; // 'smtp' | 'dev'

function isSmtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_HOST.trim());
}

function getTransporter() {
  if (transporter) return transporter;

  if (isSmtpConfigured()) {
    mode = 'smtp';
    const port = Number(process.env.SMTP_PORT) || 587;
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST.trim(),
      port,
      // secure=true cho port 465 (SMTPS); port 587 dung STARTTLS
      secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true' || port === 465,
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
        : undefined,
      requireTLS: port === 587,
      tls: { minVersion: 'TLSv1.2' },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 20000,
      // Chan doc file/URL tu noi dung mail (phong SSRF / doc file tuy y)
      disableFileAccess: true,
      disableUrlAccess: true,
    });
  } else {
    mode = 'dev';
    transporter = nodemailer.createTransport({
      streamTransport: true,
      buffer: true,
      newline: 'unix',
      disableFileAccess: true,
      disableUrlAccess: true,
    });
  }
  return transporter;
}

/** Kiem tra ket noi SMTP khi khoi dong (khong lam sap server neu loi). */
async function verifyConnection() {
  const t = getTransporter();
  if (mode === 'dev') {
    return { mode, ok: true, detail: `Che do DEV - email ghi ra ${DEV_DIR}` };
  }
  try {
    await t.verify();
    return { mode, ok: true, detail: `SMTP ${process.env.SMTP_HOST} san sang` };
  } catch (err) {
    return { mode, ok: false, detail: err.message };
  }
}

function devFilePath(tag) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const safeTag = String(tag || 'mail').replace(/[^A-Za-z0-9_-]/g, '');
  return path.join(DEV_DIR, `${stamp}_${safeTag}.eml`);
}

/**
 * Gui mot email. Tra ve { ok, mode, file? , messageId? }.
 * Khong bao gio throw ra ngoai - loi gui mail khong duoc lam vo luong dat ve.
 */
async function sendMail({ to, subject, text, html, tag }) {
  try {
    const t = getTransporter();
    const info = await t.sendMail({
      from: MAIL_FROM,
      to,
      subject,
      text,
      html,
      // Email tu dong: khong muon nhan tra loi / auto-reply
      headers: { 'Auto-Submitted': 'auto-generated' },
    });

    if (mode === 'dev') {
      fs.mkdirSync(DEV_DIR, { recursive: true });
      const file = devFilePath(tag);
      fs.writeFileSync(file, info.message);
      console.log(`[MAIL] (DEV) Da ghi email "${subject}" cho ${maskEmail(to)} -> ${file}`);
      return { ok: true, mode, file };
    }

    console.log(`[MAIL] Da gui "${subject}" cho ${maskEmail(to)} (id ${info.messageId})`);
    return { ok: true, mode, messageId: info.messageId };
  } catch (err) {
    // Log khong chua email day du
    console.error(`[MAIL] Gui email that bai cho ${maskEmail(to)}: ${err.message}`);
    return { ok: false, mode, error: err.message };
  }
}

/** Gui nhung khong cho doi ket qua (fire-and-forget). */
function sendMailAsync(opts) {
  setImmediate(() => { sendMail(opts); });
}

module.exports = { sendMail, sendMailAsync, verifyConnection, isSmtpConfigured, DEV_DIR };

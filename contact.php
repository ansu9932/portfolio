<?php
/**
 * contact.php — contact form endpoint for the Ansuman Sahoo portfolio.
 *
 *   GET  ?action=token   -> issues a signed anti-bot token (JSON)
 *   POST (form fields)    -> validates, sends 2 emails, returns JSON
 *
 * Emails sent on success:
 *   1. Notification to the site owner (Reply-To = visitor) so you can reply directly.
 *   2. Branded HTML auto-reply to the visitor.
 *
 * Bot protection: honeypot, JS-required signed token (HMAC + time window),
 * per-IP rate limiting, required AJAX header, strict validation + header-injection guard.
 */

declare(strict_types=1);

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

$config = require __DIR__ . '/config.php';
require __DIR__ . '/lib/SmtpMailer.php';

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

function json_out(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload);
    exit;
}

function client_ip(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function make_token(array $config): string
{
    $issued = time();
    $nonce  = bin2hex(random_bytes(8));
    $payload = $issued . '.' . $nonce;
    $sig = hash_hmac('sha256', $payload, $config['secret_key']);
    return $payload . '.' . $sig;
}

function verify_token(string $token, array $config): array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return [false, 'Invalid security token. Please reload the page.'];
    }
    [$issued, $nonce, $sig] = $parts;
    $expected = hash_hmac('sha256', $issued . '.' . $nonce, $config['secret_key']);
    if (!hash_equals($expected, $sig)) {
        return [false, 'Security check failed. Please reload the page.'];
    }
    $issued = (int) $issued;
    $age = time() - $issued;
    if ($age < (int) $config['min_fill_seconds']) {
        return [false, 'That was a little too fast — please try again.'];
    }
    if ($age > (int) $config['token_ttl']) {
        return [false, 'The form expired. Please reload the page and try again.'];
    }
    return [true, ''];
}

function rate_limited(array $config): bool
{
    $window = (int) $config['rate_limit_window'];
    $max    = (int) $config['rate_limit_max'];
    $file   = sys_get_temp_dir() . '/mxd_rl_' . sha1(client_ip()) . '.json';

    $now = time();
    $hits = [];
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        $decoded = $raw ? json_decode($raw, true) : null;
        if (is_array($decoded)) {
            $hits = array_filter($decoded, static fn($t) => ($now - (int) $t) < $window);
        }
    }
    if (count($hits) >= $max) {
        return true;
    }
    $hits[] = $now;
    @file_put_contents($file, json_encode(array_values($hits)), LOCK_EX);
    return false;
}

function clean(string $v): string
{
    $v = trim($v);
    $v = str_replace(["\r", "\n", "\0"], ' ', $v); // header-injection guard for single-line fields
    return $v;
}

function esc(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

/* ---------------------------------------------------------------------- */
/* GET: issue token                                                       */
/* ---------------------------------------------------------------------- */

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    if (($_GET['action'] ?? '') === 'token') {
        json_out(200, ['token' => make_token($config)]);
    }
    json_out(400, ['ok' => false, 'message' => 'Bad request.']);
}

/* ---------------------------------------------------------------------- */
/* POST: validate + send                                                  */
/* ---------------------------------------------------------------------- */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_out(405, ['ok' => false, 'message' => 'Method not allowed.']);
}

// Require the AJAX header our front-end sends (cheap bot filter).
$xrw = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
if (strtolower($xrw) !== 'xmlhttprequest') {
    json_out(400, ['ok' => false, 'message' => 'Invalid request.']);
}

// Honeypot: real users never fill this.
if (trim((string) ($_POST['company'] ?? '')) !== '') {
    // Pretend success so bots don't learn anything.
    json_out(200, ['ok' => true, 'message' => 'Thank you! Your message has been sent.']);
}

// Token
[$tokOk, $tokMsg] = verify_token((string) ($_POST['token'] ?? ''), $config);
if (!$tokOk) {
    json_out(422, ['ok' => false, 'message' => $tokMsg]);
}

// Rate limit
if (rate_limited($config)) {
    json_out(429, ['ok' => false, 'message' => 'Too many messages. Please try again later.']);
}

// Fields
$name    = clean((string) ($_POST['name'] ?? ''));
$email   = clean((string) ($_POST['email'] ?? ''));
$subject = clean((string) ($_POST['subject'] ?? ''));
$message = trim((string) ($_POST['message'] ?? ''));

$errors = [];
if ($name === '' || mb_strlen($name) > 100) {
    $errors['name'] = 'Please enter your name.';
}
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 150) {
    $errors['email'] = 'Please enter a valid email address.';
}
if ($message === '' || mb_strlen($message) < 10) {
    $errors['message'] = 'Please enter a message (at least 10 characters).';
}
if (mb_strlen($message) > 3000) {
    $errors['message'] = 'Your message is too long.';
}
if ($subject === '') {
    $subject = 'New enquiry from the website';
}
if ($errors) {
    json_out(422, ['ok' => false, 'message' => 'Please check the highlighted fields.', 'errors' => $errors]);
}

/* ---------------------------------------------------------------------- */
/* Build emails                                                           */
/* ---------------------------------------------------------------------- */

$brand   = $config['brand_color'];
$site    = $config['site_name'];
$siteUrl = $config['site_url'];
$when    = date('d M Y, H:i') . ' UTC' . (date_default_timezone_get() !== 'UTC' ? '' : '');
$ip      = client_ip();
$msgHtml = nl2br(esc($message));

/* ---- 1) Notification to the owner ---- */
$ownerSubject = 'New enquiry from ' . $name . ' — ' . $subject;
$ownerHtml = <<<HTML
<!doctype html><html><body style="margin:0;padding:0;background:#0f0f0f;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0f0f0f;padding:28px 0;font-family:Arial,Helvetica,sans-serif;">
<tr><td align="center">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#171719;border-radius:16px;overflow:hidden;border:1px solid #2a2a2d;">
    <tr><td style="padding:28px 32px;border-bottom:1px solid #2a2a2d;">
      <p style="margin:0;color:#ffffff;font-size:13px;letter-spacing:2px;text-transform:uppercase;">New website enquiry</p>
      <h1 style="margin:8px 0 0;color:{$brand};font-size:24px;">{$site}</h1>
    </td></tr>
    <tr><td style="padding:28px 32px;color:#dbd8d8;font-size:15px;line-height:1.6;">
      <p style="margin:0 0 18px;color:#8e93a1;">You received a new message through the contact form.</p>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;color:#ffffff;">
        <tr><td style="padding:8px 0;color:#8e93a1;width:120px;">Name</td><td style="padding:8px 0;">{$name}</td></tr>
        <tr><td style="padding:8px 0;color:#8e93a1;">Email</td><td style="padding:8px 0;"><a href="mailto:{$email}" style="color:{$brand};text-decoration:none;">{$email}</a></td></tr>
        <tr><td style="padding:8px 0;color:#8e93a1;">Subject</td><td style="padding:8px 0;">{$subject}</td></tr>
      </table>
      <div style="margin:20px 0;padding:18px 20px;background:#0f0f0f;border-left:3px solid {$brand};border-radius:8px;color:#ffffff;">{$msgHtml}</div>
      <p style="margin:0;color:#575960;font-size:12px;">Sent {$when} &middot; IP {$ip}</p>
    </td></tr>
    <tr><td style="padding:18px 32px;border-top:1px solid #2a2a2d;color:#575960;font-size:12px;">
      Reply directly to this email to respond to {$name}.
    </td></tr>
  </table>
</td></tr></table>
</body></html>
HTML;

/* ---- 2) Auto-reply to the visitor ---- */
$replySubject = 'Thanks for reaching out, ' . $name . ' 👋';
$nameEsc = esc($name);
$replyHtml = <<<HTML
<!doctype html><html><body style="margin:0;padding:0;background:#0f0f0f;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0f0f0f;padding:28px 0;font-family:Arial,Helvetica,sans-serif;">
<tr><td align="center">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#171719;border-radius:16px;overflow:hidden;border:1px solid #2a2a2d;">
    <tr><td style="padding:32px 32px 8px;">
      <h1 style="margin:0;color:{$brand};font-size:26px;">{$site}</h1>
    </td></tr>
    <tr><td style="padding:8px 32px 28px;color:#dbd8d8;font-size:16px;line-height:1.65;">
      <p style="margin:0 0 16px;color:#ffffff;font-size:20px;font-weight:bold;">Hi {$nameEsc}, thank you!</p>
      <p style="margin:0 0 16px;">Your message has landed safely in my inbox. I read every enquiry personally and will get back to you within 1–2 business days.</p>
      <p style="margin:0 0 8px;color:#8e93a1;font-size:13px;text-transform:uppercase;letter-spacing:1px;">Your message</p>
      <div style="margin:0 0 20px;padding:18px 20px;background:#0f0f0f;border-left:3px solid {$brand};border-radius:8px;color:#ffffff;">{$msgHtml}</div>
      <p style="margin:0 0 24px;">In the meantime, feel free to explore more of my work.</p>
      <a href="{$siteUrl}" style="display:inline-block;background:{$brand};color:#ffffff;text-decoration:none;padding:13px 26px;border-radius:40px;font-weight:bold;font-size:14px;">Visit the website</a>
    </td></tr>
    <tr><td style="padding:20px 32px;border-top:1px solid #2a2a2d;color:#575960;font-size:12px;">
      This is an automated confirmation from {$site}. You can simply reply if you'd like to add anything.
    </td></tr>
  </table>
</td></tr></table>
</body></html>
HTML;

/* ---------------------------------------------------------------------- */
/* Send                                                                   */
/* ---------------------------------------------------------------------- */

$mailer = new SmtpMailer(
    $config['smtp_host'],
    $config['smtp_port'],
    $config['smtp_user'],
    $config['smtp_pass'],
    $config['smtp_secure']
);
$mailer->setFrom($config['from_email'], $config['from_name']);
$mailer->addTo($config['notify_email'], $config['notify_name']);
$mailer->addReplyTo($email, $name);
$mailer->setSubject($ownerSubject);
$mailer->setHtml($ownerHtml);

if (!$mailer->send()) {
    error_log('[contact] owner mail failed: ' . $mailer->getError());
    json_out(502, ['ok' => false, 'message' => 'Sorry, the message could not be sent right now. Please email me directly.']);
}

// Auto-reply (best-effort: don't fail the request if this one bounces).
$reply = new SmtpMailer(
    $config['smtp_host'],
    $config['smtp_port'],
    $config['smtp_user'],
    $config['smtp_pass'],
    $config['smtp_secure']
);
$reply->setFrom($config['from_email'], $config['from_name']);
$reply->addTo($email, $name);
$reply->addReplyTo($config['notify_email'], $config['notify_name']);
$reply->setSubject($replySubject);
$reply->setHtml($replyHtml);
if (!$reply->send()) {
    error_log('[contact] auto-reply failed: ' . $reply->getError());
}

json_out(200, ['ok' => true, 'message' => 'Thank you! Your message has been sent — check your inbox for a confirmation.']);

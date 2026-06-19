<?php
/**
 * Contact form configuration — TEMPLATE.
 *
 * Copy this file to "config.php" and fill in your real values.
 * config.php is git-ignored on purpose so your password is never committed.
 *
 * On Hostinger: upload config.php into the same folder as contact.php
 * (it will NOT be in the public repo).
 */

return array(

    // --- SMTP (outgoing mail) --------------------------------------------
    // Hostinger outgoing server. Port 465 uses implicit SSL ("ssl").
    'smtp_host'   => 'smtp.hostinger.com',
    'smtp_port'   => 465,
    'smtp_secure' => 'ssl',                 // 'ssl' for 465, 'tls' for 587
    'smtp_user'   => 'info@example.com',    // your mailbox login
    'smtp_pass'   => 'CHANGE_ME',           // your mailbox password

    // --- Addresses -------------------------------------------------------
    // The "From" must be the authenticated mailbox above (Hostinger requirement).
    'from_email'  => 'info@example.com',
    'from_name'   => 'Your Name',

    // Where enquiry notifications are delivered (your personal inbox).
    'notify_email' => 'you@example.com',
    'notify_name'  => 'Your Name',

    // Shown to the visitor in the auto-reply / branding.
    'site_name'   => 'Your Name',
    'site_url'    => 'https://example.com',
    'brand_color' => '#002bba',

    // --- Security --------------------------------------------------------
    // Long random string used to sign anti-bot tokens. Generate a new one, e.g.
    // php -r "echo bin2hex(random_bytes(32));"
    'secret_key'  => 'REPLACE_WITH_A_LONG_RANDOM_STRING',

    // Rate limit: max submissions per IP within the window (seconds).
    'rate_limit_max'    => 5,
    'rate_limit_window' => 600,             // 10 minutes

    // Min seconds a human needs between loading the form and submitting.
    'min_fill_seconds'  => 3,
    // Token validity (seconds) after it is issued.
    'token_ttl'         => 7200,            // 2 hours
);

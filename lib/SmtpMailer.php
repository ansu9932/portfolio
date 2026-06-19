<?php
/**
 * SmtpMailer — a tiny, dependency-free SMTP client.
 *
 * Speaks just enough SMTP (EHLO, AUTH LOGIN, MAIL FROM, RCPT TO, DATA) to
 * deliver an HTML email through an authenticated server such as Hostinger.
 * Designed for shared hosting where Composer / PHPMailer may not be available.
 *
 * Supports:
 *   - Implicit TLS  (port 465, "ssl")  -> recommended for Hostinger
 *   - STARTTLS      (port 587, "tls")
 *   - multipart/alternative (HTML + plain-text fallback)
 *
 * Usage:
 *   $m = new SmtpMailer($host, $port, $user, $pass, 'ssl');
 *   $m->setFrom('info@example.com', 'My Site');
 *   $m->addTo('you@example.com');
 *   $m->addReplyTo('visitor@example.com', 'Visitor Name');
 *   $m->setSubject('Hello');
 *   $m->setHtml('<p>Hi</p>');
 *   if (!$m->send()) { echo $m->getError(); }
 */
class SmtpMailer
{
    private $host;
    private $port;
    private $user;
    private $pass;
    private $secure;      // 'ssl' | 'tls' | ''
    private $timeout = 20;

    private $fromEmail = '';
    private $fromName  = '';
    private $to        = array(); // list of [email, name]
    private $replyTo   = array(); // list of [email, name]
    private $subject   = '';
    private $html      = '';
    private $text      = '';

    private $error     = '';
    private $debug     = array();

    public function __construct($host, $port, $user, $pass, $secure = 'ssl')
    {
        $this->host   = $host;
        $this->port   = (int) $port;
        $this->user   = $user;
        $this->pass   = $pass;
        $this->secure = strtolower($secure);
    }

    public function setFrom($email, $name = '')      { $this->fromEmail = $email; $this->fromName = $name; }
    public function addTo($email, $name = '')        { $this->to[] = array($email, $name); }
    public function addReplyTo($email, $name = '')   { $this->replyTo[] = array($email, $name); }
    public function setSubject($subject)             { $this->subject = $subject; }
    public function setHtml($html)                   { $this->html = $html; }
    public function setText($text)                   { $this->text = $text; }
    public function getError()                       { return $this->error; }
    public function getDebug()                       { return $this->debug; }

    public function send()
    {
        if ($this->fromEmail === '' || empty($this->to)) {
            $this->error = 'Missing sender or recipient.';
            return false;
        }

        $remote = ($this->secure === 'ssl' ? 'ssl://' : '') . $this->host . ':' . $this->port;
        $ctx = stream_context_create(array(
            'ssl' => array(
                'verify_peer'       => true,
                'verify_peer_name'  => true,
                'allow_self_signed' => false,
            ),
        ));

        $errno = 0; $errstr = '';
        $conn = @stream_socket_client($remote, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $ctx);
        if (!$conn) {
            $this->error = "Connection failed: $errstr ($errno)";
            return false;
        }
        stream_set_timeout($conn, $this->timeout);

        try {
            $this->expect($conn, 220);

            $ehloHost = $this->ehloName();
            $this->cmd($conn, "EHLO $ehloHost", 250);

            if ($this->secure === 'tls') {
                $this->cmd($conn, 'STARTTLS', 220);
                if (!stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new Exception('Unable to start TLS encryption.');
                }
                $this->cmd($conn, "EHLO $ehloHost", 250);
            }

            // AUTH LOGIN
            $this->cmd($conn, 'AUTH LOGIN', 334);
            $this->cmd($conn, base64_encode($this->user), 334);
            $this->cmd($conn, base64_encode($this->pass), 235);

            // Envelope
            $this->cmd($conn, 'MAIL FROM:<' . $this->fromEmail . '>', 250);
            foreach ($this->to as $rcpt) {
                $this->cmd($conn, 'RCPT TO:<' . $rcpt[0] . '>', array(250, 251));
            }

            // Data
            $this->cmd($conn, 'DATA', 354);
            $this->write($conn, $this->buildMessage() . "\r\n.");
            $this->expect($conn, 250);

            $this->cmd($conn, 'QUIT', array(221, 250));
        } catch (Exception $e) {
            $this->error = $e->getMessage();
            @fclose($conn);
            return false;
        }

        @fclose($conn);
        return true;
    }

    /* ----------------------------------------------------------------- */

    private function ehloName()
    {
        $h = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
        $h = preg_replace('/[^A-Za-z0-9.\-]/', '', $h);
        return $h !== '' ? $h : 'localhost';
    }

    private function buildMessage()
    {
        $eol = "\r\n";
        $boundary = '=_mxd_' . bin2hex(random_bytes(12));

        $headers   = array();
        $headers[] = 'Date: ' . date('r');
        $headers[] = 'From: ' . $this->formatAddress($this->fromEmail, $this->fromName);
        $headers[] = 'To: ' . $this->formatAddressList($this->to);
        if (!empty($this->replyTo)) {
            $headers[] = 'Reply-To: ' . $this->formatAddressList($this->replyTo);
        }
        $headers[] = 'Subject: ' . $this->encodeHeader($this->subject);
        $headers[] = 'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . $this->ehloName() . '>';
        $headers[] = 'MIME-Version: 1.0';

        $text = $this->text !== '' ? $this->text : trim(html_entity_decode(strip_tags($this->html), ENT_QUOTES, 'UTF-8'));

        if ($this->html !== '') {
            $headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';
            $body  = '--' . $boundary . $eol;
            $body .= 'Content-Type: text/plain; charset=UTF-8' . $eol;
            $body .= 'Content-Transfer-Encoding: base64' . $eol . $eol;
            $body .= chunk_split(base64_encode($text)) . $eol;
            $body .= '--' . $boundary . $eol;
            $body .= 'Content-Type: text/html; charset=UTF-8' . $eol;
            $body .= 'Content-Transfer-Encoding: base64' . $eol . $eol;
            $body .= chunk_split(base64_encode($this->html)) . $eol;
            $body .= '--' . $boundary . '--' . $eol;
        } else {
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: base64';
            $body = chunk_split(base64_encode($text));
        }

        // dot-stuffing for lines beginning with "."
        $message = implode($eol, $headers) . $eol . $eol . $body;
        $message = preg_replace('/^\./m', '..', $message);
        return $message;
    }

    private function formatAddress($email, $name)
    {
        $email = $this->sanitizeEmail($email);
        if ($name === '') return $email;
        return $this->encodeHeader($name) . ' <' . $email . '>';
    }

    private function formatAddressList($list)
    {
        $out = array();
        foreach ($list as $a) {
            $out[] = $this->formatAddress($a[0], isset($a[1]) ? $a[1] : '');
        }
        return implode(', ', $out);
    }

    private function sanitizeEmail($email)
    {
        // strip anything that could enable header injection
        return preg_replace('/[\r\n]+/', '', trim($email));
    }

    private function encodeHeader($value)
    {
        $value = str_replace(array("\r", "\n"), '', $value);
        if (preg_match('/[^\x20-\x7E]/', $value)) {
            return '=?UTF-8?B?' . base64_encode($value) . '?=';
        }
        return $value;
    }

    private function cmd($conn, $command, $expected)
    {
        $this->write($conn, $command);
        return $this->expect($conn, $expected);
    }

    private function write($conn, $data)
    {
        if (fwrite($conn, $data . "\r\n") === false) {
            throw new Exception('Failed to write to SMTP socket.');
        }
    }

    private function expect($conn, $codes)
    {
        if (!is_array($codes)) $codes = array($codes);

        $response = '';
        while (($line = fgets($conn, 515)) !== false) {
            $response .= $line;
            $this->debug[] = rtrim($line);
            // multiline replies use "250-" ; final line uses "250 "
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        if ($response === '') {
            throw new Exception('Empty SMTP response (timeout?).');
        }

        $code = (int) substr($response, 0, 3);
        if (!in_array($code, $codes, true)) {
            throw new Exception('Unexpected SMTP reply: ' . trim($response));
        }
        return $code;
    }
}

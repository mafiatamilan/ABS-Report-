# Security Assessment Report: absvidhyamandhir.org
**Date:** February 2, 2026
**Researcher:** Yogeshwaran
**Target:** https://absvidhyamandhir.org
**Severity:** High (Action Required)

---

## 1. Executive Summary
A passive security audit and reconnaissance of the school's public web infrastructure revealed several high-risk misconfigurations. The most critical finding is a **Publicly Accessible Error Log** that leaks internal server paths and identifies vulnerable scripts. Additionally, the use of **Outdated JavaScript Libraries** exposes the site's users to Cross-Site Scripting (XSS).

---

## 2. Technical Findings

### 🔴 2.1 Sensitive Information Disclosure (Public Error Log)
*   **Vulnerability:** The server's error log is publicly readable.
*   **Endpoint:** `https://absvidhyamandhir.org/error_log`
*   **Impact:** **CRITICAL**.
    *   **Full Path Disclosure (FPD):** Reveals the internal directory structure: `/home/vjmtechin93/public_html/...`
    *   **Username Leakage:** Identifies the system user as `vjmtechin93`.
    *   **Exploit Mapping:** Identifies specific scripts (`mail.php`, `mail_admission.php`) that are currently failing due to unhandled variables, providing a direct target for input manipulation attacks.
*   **Remediation:**
    1. Delete the `error_log` file immediately.
    2. Add the following to the `.htaccess` file to prevent future access:
       ```apache
       <Files "error_log">
           Order Allow,Deny
           Deny from all
       </Files>
       ```

### 🔴 2.2 Outdated & Vulnerable JavaScript Libraries
*   **Vulnerability:** The site employs legacy versions of core libraries.
*   **Components:**
    *   **jQuery v2.1.4** (Known for CVE-2015-9251, CVE-2020-11022)
    *   **Bootstrap v4.0.0** (Known for XSS in data attributes)
*   **Impact:** **HIGH**. An attacker can leverage these well-documented vulnerabilities to execute arbitrary JavaScript in the context of the user's browser, potentially leading to session theft.
*   **Remediation:** Upgrade to **jQuery 3.7.1** and **Bootstrap 5.3**.

### 🟠 2.3 Orphaned Backend Scripts
*   **Vulnerability:** Scripts like `mail.php` and `mail_admission.php` are accessible directly via URL.
*   **Impact:** **MEDIUM**. These scripts handle sensitive data (Admission enquiries) but do not appear to have CSRF protection or strict input validation.
*   **Remediation:** Implement server-side validation and CSRF tokens for all form-processing scripts.

### 🟠 2.4 Server Fingerprinting
*   **Vulnerability:** Response headers reveal exact software versions.
*   **Headers:** `x-powered-by: PHP/8.2.27`, `server: LiteSpeed`.
*   **Impact:** Assists attackers in tailoring exploits for specific version vulnerabilities.
*   **Remediation:** Set `expose_php = Off` in `php.ini` and disable server signature in LiteSpeed settings.

---

## 3. Recommended Security Header Implementation
The site currently lacks "Defense in Depth" headers. It is recommended to add the following to the web server configuration:

| Header | Purpose |
| :--- | :--- |
| `X-Frame-Options: DENY` | Prevents Clickjacking attacks. |
| `Strict-Transport-Security` | Forces HTTPS usage (prevents SSL Stripping). |
| `X-Content-Type-Options: nosniff` | Prevents browsers from "guessing" file types (prevents XSS). |

---

## 4. Conclusion
The current security posture of the website is **vulnerable to targeted exploitation**. The exposure of the `error_log` significantly lowers the bar for an attacker to find and exploit further bugs in the `mail.php` handling logic. Immediate remediation of Section 2.1 and 2.2 is highly recommended.

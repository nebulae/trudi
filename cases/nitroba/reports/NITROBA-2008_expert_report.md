# NITROBA-2008 — Network Forensic Expert Report

**Case ID:** NITROBA-2008
**Examiner:** TRUDI DFIR Orchestrator (SANS SIFT)
**Date:** 2026-06-11
**Evidence:** `nitroba.pcap` — Ethernet-tap capture, 56,180,821 bytes
**Integrity:** MD5 `9981827f11968773ff815e39f5458ec8` · SHA1 `65656392412add15f93f8585197a8998aaeb50a1` · SHA256 `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb` (verified at intake)
**Case question:** *Which device/person on the shared G24 open Wi-Fi sent the harassing willselfdestruct.com / sendanonymousemail message to Lily Tuckrige, and which CHEM109 roster member is that identity?*

All times in this report are **UTC (GMT)**. The capture's packet-display clock is **UTC−7**, established from the capture's own in-band HTTP `Date:` response headers (packets displayed at 18:51 local carry `Date: …01:51 GMT`; the harassment-window flows carry `Date: …06:01–06:10 GMT`).

---

## 1. Executive Summary

A harassing email was sent to the victim **lilytuckrige@yahoo.com** on **2008-07-22 ~06:01 GMT** through the anonymous web relay **www.sendanonymousemail.net**, with a spoofed sender of `the_whole_world_is_watching@nitroba.org`, subject *"Your class stinks"* and body *"Why do you persist in teaching a boring class? We don't like it. We don't like you."* The same browser then visited **www.willselfdestruct.com** three minutes later.

The submission originated from internal address **192.168.15.4** — a **shared NAT egress** for the dorm's open Wi-Fi (it fronts at least two physical machines). The specific machine that sent the message ran **Internet Explorer 6 on Windows XP**, and that exact browser was, **~33 seconds earlier**, signed in to Gmail as **`jcoachj@gmail.com`**. The username `jcoachj` matches **CHEM109 roster member Johnny Coach**.

> **Conclusion — LIKELY: the harassing message was sent by Johnny Coach (`jcoachj@gmail.com`).**
> The attribution is **LIKELY**, not certain, because (a) the Wi-Fi is open and the IP is shared, so identity rests on the browser session rather than the address, and (b) the username→person mapping should be corroborated by a Google account-ownership subpoena.

Two other identities on the same NAT were examined and **excluded as the sender**: `amy789smith` (Amy Smith, Yahoo) and `beth@bethr.org` (Facebook, on a separate Mac).

---

## 2. Findings and Confidence Tiers

| # | Finding | Tier |
|---|---------|------|
| 1 | Harassing email sent from **192.168.15.4** to **lilytuckrige@yahoo.com** via HTTP `POST /send.php` to **www.sendanonymousemail.net** — spoofed sender `the_whole_world_is_watching@nitroba.org`, subject *"Your class stinks"*, body *"Why do you persist in teaching a boring class? We don't like it. We don't like you."* (~06:01:26 GMT). Same host then `GET /secure/submit` to **www.willselfdestruct.com** (~06:04:07 GMT). | **CONFIRMED** |
| 2 | The same **MSIE 6.0 / Windows XP** browser on 192.168.15.4 held an authenticated **Gmail session as `jcoachj@gmail.com`** (`gausr=jcoachj@gmail.com` + `GMAIL_LOGIN` cookie, compose tab `/mail/?tab=cm`) **~33 s before** the harassment POST. | **CONFIRMED** |
| 3 | The NAT also ran a Yahoo Messenger session as **`amy789smith`** (profile *Amy/Smith*; **buddy list includes the victim `lilytuckrige`**; address book includes `avabook3@gmail.com` / *Ava Book*), starting **06:09:58 GMT — ~8.5 min *after* the send**. | **CONFIRMED** |
| 4 | **192.168.15.4 is a shared NAT egress**, presenting two mutually-exclusive fingerprints — `MSIE 6.0; Windows NT 5.1` and `Firefox/2.0.0.16; Intel Mac OS X`. All harassment vectors carry the **MSIE6/WinXP** fingerprint. Attribution rests on browser continuity, not the IP. | **LIKELY** |
| 5 | **Sender ≈ Johnny Coach** (`jcoachj@gmail.com`): the contemporaneous authenticated identity in the sending browser. Capped at LIKELY by the open Wi-Fi and the username-pattern (not yet subpoena-confirmed) account binding. | **LIKELY** |
| 6 | **H2 refuted** — Amy Smith was not the send-time operator (her Yahoo session postdates the send by ~8.5 min). | **LIKELY (refutation)** |
| 7 | **H3 refuted** — not a transient wardriver; the MSIE6/WinXP host shows sustained, authenticated personal-account use. | **LIKELY (refutation)** |
| 8 | **`beth@bethr.org`** (Facebook `c_user=588141158`) was on a **separate Mac/Firefox host** behind the same NAT; not a roster name; no anonymous-mailer traffic from that fingerprint. **Excluded** as a co-tenant. | **LIKELY (exclusion)** |
| 9 | Second internal device **192.168.1.64** (`mylady.ixchel@gmail.com` / AOL `m57jean`) is a separate, unrelated principal. **Excluded.** | **LIKELY (exclusion)** |
| 10 | No cleartext SMTP (zero port-25 connections) and no Hotmail/Live/AOL webmail-send channel from 192.168.15.4; the only delivery channels were sendanonymousemail.net and willselfdestruct.com. | **UNCONFIRMED (negative)** |

---

## 3. Reconstructed Timeline (2008-07-22 UTC)

| Time (GMT) | Event | Browser / UA |
|---|---|---|
| 06:00:53 | Gmail **compose** tab `/mail/?tab=cm` opened as **`jcoachj@gmail.com`** (`gausr=jcoachj@gmail.com`, `GMAIL_LOGIN` cookie) | MSIE 6.0 / Win XP |
| 06:01:26 | sendanonymousemail.net form loaded; **`POST /send.php`** → harassing email **to lilytuckrige@yahoo.com**, spoofed sender `the_whole_world_is_watching@nitroba.org` | MSIE 6.0 / Win XP |
| 06:04:07 | Navigated to **www.willselfdestruct.com** `GET /secure/submit` (second anonymizer) | MSIE 6.0 / Win XP |
| 06:09:58 | Yahoo Messenger login as **`amy789smith`** (Amy Smith); buddy list includes victim | YMSG client |

The sender first reached the anonymizers via a Google search for **"send anonymous mail"** and the About.com "anonymous email services" guide — both from the same MSIE6/WinXP browser.

---

## 4. Method (and Reliability / Reproducibility)

1. **Integrity** — evidence hashed at intake (read-only handling throughout; all output to `analysis/`, `exports/`, `reports/`).
2. **Anchor confirmation** — `net.ngrep_search` located the willselfdestruct.com and sendanonymousemail.net activity and the verbatim `POST /send.php` body.
3. **Topology / device mapping** — `net.tcpdump_extract_ips`, `net.tcpdump_list_connections` isolated 192.168.15.4 as the source.
4. **Identity inventory** — `net.http_session_inventory` (733 sessions) and `net.pcap_identity_timeline` enumerated every cookie, login parameter, and email per host.
5. **Knowns-driven roster hunt** — `misc.knowns_pattern_generate` derived 99 username variants from the CHEM109 roster; cross-reference matched **only** `jcoachj` (Johnny Coach) and `amy789smith` (Amy Smith) on the suspect NAT.
6. **Timeline ordering** — `net.tcpdump_read` packet timestamps, normalized to GMT via in-band server `Date:` headers, established the send-then-Yahoo ordering.
7. **Browser-fingerprint separation** — User-Agent analysis distinguished the MSIE6/WinXP harasser from the Mac/Firefox `beth@bethr.org` co-tenant.

**Independent corroboration of the same result (Part-2 reliability requirement):** the harassment vector is proven by the **plaintext HTTP POST body** (direct content evidence); the operator identity is independently shown by **(a)** the `gausr=jcoachj@gmail.com` URL parameter, **(b)** the `GMAIL_LOGIN` session cookie, and **(c)** User-Agent + source-IP + sub-minute timing continuity between the Gmail session and the POST — three distinct artifact families converging on the same MSIE6/WinXP host.

**Self-corrections during the examination (audit trail):** (i) an initial willselfdestruct "submission" claim was downgraded to "navigated to" when only a `GET` (no POST body) was captured; (ii) an adversarial timezone challenge was resolved against in-band `Date:` headers; (iii) the "single device" model was corrected to a **shared NAT** after two mutually-exclusive OS fingerprints were found.

---

## 5. Limitations

- **Open Wi-Fi / shared IP:** 192.168.15.4 is a NAT egress for multiple devices. Network evidence binds the act to a **browser/host**, not directly to a person. The `jcoachj@gmail.com` session is the load-bearing link.
- **Username ≠ proven ownership:** `jcoachj` → Johnny Coach is a roster pattern match; account ownership requires provider records.
- **PCAP-only:** no disk/host artifacts; no DHCP/ARP MAC lease was present to bind 192.168.15.4 to a specific NIC.

## 6. Recommended Next Steps (advisory)

- **Subpoena Google** for `jcoachj@gmail.com` subscriber and login records spanning 06:00–06:05 GMT 2008-07-22.
- **Subpoena sendanonymousemail.net** for the 06:01 submission record (source IP, form fields, metadata).
- Treat **Amy Smith** and **beth@bethr.org** as witnesses/co-tenants, not suspects (ordering and separate-host evidence exclude them).
- **Preserve** the PCAP, hash manifest, and this audit trail for the NCAT proceeding.
- **Remediation:** move the dorm from open Wi-Fi to authenticated 802.1X with DHCP/MAC logging so future attribution does not depend on third-party webmail correlation.

---

*Audit trail:* `reports/NITROBA-2008_trace.json` / `.md` (83 entries, 26 tool calls) — every finding above is traceable to the specific tool execution (`_trudi_call_id`) that produced it.

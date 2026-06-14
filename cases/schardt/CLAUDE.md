## SCHARDT-2002 Case Context

**Case ID:** SCHARDT-2002
**Evidence type:** Single-host disk image (no memory, no network capture)
**Evidence root:** `/home/trin/cases/schardt/evidence/`

---

### Scenario (verbatim from NIST)

On **09/20/2004**, a **Dell CPi notebook computer, serial # VLQLW**, was found abandoned along with a **wireless PCMCIA card** and an **external homemade 802.11b antenna**. It is suspected the computer was used for hacking purposes, although it cannot yet be tied to a hacking suspect, **Greg Schardt**. Schardt also goes by the online nickname of **"Mr. Evil"** and some of his associates have said that he would park his vehicle within range of Wireless Access Points (like Starbucks and other T-Mobile Hotspots) where he would then intercept internet traffic, attempting to get credit card numbers, usernames & passwords.

> *Find any hacking software, evidence of their use, and any data that might have been generated. Attempt to tie the computer to the suspect, Greg Schardt.*

NIST's published HTML obfuscates the name as `G=r=e=g S=c=h=a=r=d=t` to defeat web crawlers — **the equal signs do NOT appear in the image files**. Search the image for the plain string `Greg Schardt`.

---

### Case Question

**CASE_QUESTION: Find hacking software, evidence of its use, and any captured data on the abandoned Dell CPi laptop, and produce evidence tying the laptop to Greg Schardt (alias "Mr. Evil").**

---

### Evidence Inventory

| File | Format | Size | Notes |
|------|--------|------|-------|
| `4Dell Latitude CPi.E01` | EnCase E01 segment 1 | 671 MB | Primary image |
| `4Dell Latitude CPi.E02` | EnCase E01 segment 2 | 419 MB | Continuation |
| `SCHARDT.001` – `SCHARDT.008` | Raw `dd` split (650 MB each) | ~5.0 GB total | Same drive, alternate format. NIST page lists 7 parts but **8 segments are present** — `.008` is the trailing partial segment. |
| `SCHARDT.LOG` | Forensic MD5 imager log | 4.6 KB | Imager metadata |
| `HackingCase_E01_hashes.html` | Reference hashes (HashMyFiles) | 2.4 KB | Vendor-published MD5 / SHA-1 / SHA-256 |

**Vendor-published hashes (E01, from `HackingCase_E01_hashes.html`):**

| Segment | MD5 | SHA-256 |
|---------|-----|---------|
| `4Dell Latitude CPi.E01` | `943243e71eda7481fee7b83f0669893` | `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31` |
| `4Dell Latitude CPi.E02` | `4931253cc91dffdef5867c3dfbd9951` | `46bd09821dbb64675e5877d0ad7ec544a571fad5a3fd7fc3f0c3a162788887db5` |

**Acquisition (from `SCHARDT.LOG`):** Forensic MD5 imager v1.77, S/N 50527. Source drive **IBM-DBCA-204860**, S/N **HQ0RQQF7429**, 4.5 GB, 9,514,260 sectors. Mode: DD image, 650 MB segments, MD5 verification.


---

### 31 NIST Questions (canonical sub-objectives)

These are the authoritative questions from the NIST page. Each becomes a tracked finding.

**System profile**
1. What is the image hash? Does acquisition and verification hash match?
2. What operating system was used on the computer?
3. When was the install date?
4. What is the timezone setting?
5. Who is the registered owner?
6. What is the computer account name?
7. What is the primary domain name?
8. When was the last recorded computer shutdown date/time?
9. How many accounts are recorded (total number)?
10. What is the account name of the user who mostly uses the computer?
11. Who was the last user to logon to the computer?

**Identity linkage (Schardt = Mr. Evil = admin)**
12. A search for "Greg Schardt" reveals multiple hits. One file proves Schardt = Mr. Evil = administrator. What file is it, and what software does it belong to?

**Network identity**
13. List the network cards used by this computer.
14. The same file from Q12 reports the IP address and MAC address. What are they?
15. The first 3 hex bytes of the MAC reveal the vendor. Which NIC was used during the install/setup for **LOOK@LAN**?

**Hacking tools**
16. Find **six** installed programs that may be used for hacking.

**Email / news**
17. SMTP email address for Mr. Evil?
18. NNTP (news-server) settings for Mr. Evil?
19. Which two installed programs show this information?
20. List five newsgroups Mr. Evil subscribed to.

**IRC (mIRC)**
21. mIRC was installed. What user settings were shown when the user was online in a chat channel?
22. List three IRC channels the user accessed (mIRC logs sessions).

**Packet sniffing (Ethereal)**
23. Ethereal default save directory is `\My Documents`. What is the name of the file containing the intercepted data?
24. Viewing that file as text reveals the victim. What type of wireless computer was the victim using?
25. What websites was the victim accessing?

**Web mail**
26. Search for the main user's web-based email address. What is it?
27. Yahoo mail saves copies of email under what file name?

**Deleted / recycle bin**
28. How many executable files are in the recycle bin?
29. Are these files really deleted?
30. How many files are actually reported to be deleted by the file system?

**Anti-virus**
31. Perform an AV check. Are there any viruses on the computer?

---

### Knowns-Driven IOC Seeds (from the scenario + questions)

Use `misc.knowns_pattern_generate` to derive variants before broad enumeration.

- **Identity strings** — `Greg Schardt`, `Schardt`, `Mr. Evil`, `MrEvil`, `mr.evil`, `mrevil`
- **Hardware** — `Dell CPi`, `Dell Latitude CPi`, serial `VLQLW`, drive `IBM-DBCA-204860`, drive serial `HQ0RQQF7429`
- **Network venues mentioned** — `Starbucks`, `T-Mobile`, `T-Mobile Hotspot`

---

### Investigation Strategy

- Single-host disk-only case — Windows artifacts carry the entire investigation. No memory image (no `vol.*`). No PCAP unless recovered from disk.
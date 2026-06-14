## NITROBA-2008 Case Context

**Case ID:** NITROBA-2008  
**Evidence:** `/home/trin/cases/nitroba/evidence/nitroba.pcap` (54 MB, Ethernet tap capture)  
**Victim:** Lily Tuckrige, Chemistry 109 instructor, Nitroba State University  
**Victim email:** lilytuckrige@yahoo.com  
**Incident:** Harassing emails sent from IP 140.247.62.34 (G24.student.nitroba.org — shared dorm room)

### Known IOCs
- Originating IP: `140.247.62.34` (resolves to G24.student.nitroba.org)
- First email: `nobody@nitroba.org`, subject "we don't like your class", Sun 13 Jul 2008 17:21:01 UTC
- Second email: via willselfdestruct.com (noreply@willselfdestruct.com), subject "you can't find us", Mon 21 Jul 2008 (message body: "and you can't hide from us. Stop teaching. Start running.")
- SMTP relay used for first email: `140.247.62.34` (HELO nobody) → Yahoo MX mta368.mail.re4.yahoo.com

### Dorm Room G24 — Suspects
Three occupants share the room. An open (no password) Wi-Fi router was installed by Barbara's boyfriend Kenny. Any device on that Wi-Fi shares the dorm's IP.
- Alice (last name unknown)
- Barbara (last name unknown)
- Candice (last name unknown)

### CHEM109 Class List (potential suspects)
Amy Smith, Burt Greedom, Tuck Gorge, Ava Book, Johnny Coach, Jeremy Ledvkin, Nancy Colburne, Tamara Perkins, Esther Pringle, Asar Misrad, Jenny Kant

### Investigation Objectives
1. Map the dorm room network from PCAP (identify devices by MAC/IP)
2. Find the TCP flow containing the hostile willselfdestruct.com submission
3. Tie that flow to a specific web browser / device (User-Agent, cookies, other HTTP metadata)
4. Identify other TCP connections from the same device that reveal the sender's identity
5. Match the identified person to the CHEM109 class list

### Legal Context (Part 2)
The identified suspect was suspended; they are appealing to the NSW Civil and Administrative Tribunal (NCAT). The expert report must:
1. Detail analysis/examinations that led to identification of the sender
2. Demonstrate reliability via alternate tools/methods arriving at the same result
3. Treat the NITROBA.PCAP as reliable as-provided (chain of custody assumed intact at acquisition)

### Network Forensics Notes
- Evidence is a PCAP only — no disk image, no memory image
- Primary TRUDI namespaces: `net.*`, `strings.*`, `carve.*`
- No `vol.*`, `ez.*`, `tsk.*` applicable (no host image)
- SMTP, HTTP, DNS analysis are the primary artifact types
- Open Wi-Fi complicates attribution — must identify specific device, not just IP

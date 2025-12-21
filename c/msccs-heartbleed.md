# HEARTBLEED: OUT-OF-BOUNDS READ IN OPENSSL

### Introduction:

C is a memory-unsafe language (it does not prevent invalid memory accesses by default), so if a memory access check is missing or incorrectly performed, an adversary might be able to read information they are not authorized to receive. Failing to restrict reading to the valid range of a memory buffer is called "Out-of-Bounds-Read" (CWE-125) and is routinely in the CWE Top 25 Most Dangerous Software Weaknesses. OpenSSL is a widely-used cryptographic library. This case study discusses the Heartbleed vulnerability ([CVE-2014-0160](https://www.cve.org/CVERecord?id=CVE-2014-0160)), a critical security flaw in OpenSSL in where adversaries were allowed to request information (a "read") beyond the range of a memory buffer that was stored in a region of memory called the "heap".

### Software:

**Name:** OpenSSL

**Language:** C

**URL:** https://www.openssl.org/

**Versions:** Versions 1.0.1 through 1.0.1f (inclusive) are vulnerable. The vulnerability was introduced in December 2011, and was released in version 1.0.1 on 2012-03-14. OpenSSL version 1.0.1g, released 2014-04-07, fixes the vulnerability.

### Weakness:

The fundamental weakness in this case study is [**CWE-126: Buffer Over-read**](https://cwe.mitre.org/data/definitions/126.html). This occurs when software reads data outside the intended memory buffer (typically beyond its end) because it trusted attacker-supplied data to determine the end, instead of trustworthy data.

This vulnerability was reached because of two other weaknesses:

* [**CWE-20: Improper Input Validation**](https://cwe.mitre.org/data/definitions/20.html), where the software fails to validate input data.
* [**CWE-130: Improper Handling of Length Parameter Inconsistency**](https://cwe.mitre.org/data/definitions/130.html), where the software fails to resolve inconsistency between length information provided.

### Vulnerability:

The Heartbleed vulnerability ([CVE-2014-0160](https://www.cve.org/CVERecord?id=CVE-2014-0160)) of OpenSSL involved incorrect handling of a "heartbeat" request. OpenSSL implements the TLS protocol for security. An optional feature of the protocol is a "hearbeat" request, where the requester provides can provide a string and its length, and the system is to respond with the same string and the length. Unfortunately, an attacker could provide a string and claim an excessively-long length of the string being provided. When the vulnerable versions of OpenSSL received a heartbeat request from the network, it failed to verify that the requested length of the payload matched the length of the data provided (CWE-126) as was required by the specification. As a result, it would reply with additional data beyond the intended memory buffer. Since OpenSSF is a cryptographic library, this other data often had secrets such as private keys, session ids, passwords, and so on.

It was possible to reach this vulnerability because:

* The library failed to validate the "payload length" field of the TLS Heartbeat record (CWE-20)
* The library did not resolve the inconsistency between the heartbeat message's specified length and its actual record length (CWE-130)

More specifically, the vulnerability existed in the function `dtls1_process_heartbeat` (in `d1_both.c`) and function `tls1_process_heartbeat` (in `t1_lib.c`) functions. For our purposes, we'll focus on the first function, since that illustrates the issue.

The OpenSSL code, after loading its payload type, would read two bytes from the incoming message to determine the payload length (using the code `n2s(p, payload)` on line 1335). It then allocated a buffer (line 1353) and eventually used `memcpy` (line 1358) to copy the payload into a response. Because the code never checked if the outgoing record could store a response, or if the incoming record actually contained as many bytes as the `payload` variable claimed, `memcpy` would simply keep reading from the heap memory following the actual message. The result would be that the attacker would receive excess unauthorized data.

Here is the vulnerable C code in [commit 4d6c12f3088d3ee5](https://github.com/openssl/openssl/commit/4e6c12f3088d3ee5747ec9e16d03fc671b8f40be) in file [ssl/d1_both.c](https://github.com/openssl/openssl/blob/4e6c12f3088d3ee5747ec9e16d03fc671b8f40be/ssl/d1_both.c) just before it was fixed:

```c
 1325 int
 1326 dtls1_process_heartbeat(SSL *s)
 1327     {
 1328     unsigned char *p = &s->s3->rrec.data[0], *pl;
 1329     unsigned short hbtype;
 1330     unsigned int payload;
 1331     unsigned int padding = 16; /* Use minimum padding */
 1332 
 1333     /* Read type and payload length first */
 1334     hbtype = *p++;
 1335     n2s(p, payload);
 1336     pl = p;
 1337 
 1338     if (s->msg_callback)
 1339      s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
 1340       &s->s3->rrec.data[0], s->s3->rrec.length,
 1341       s, s->msg_callback_arg);
 1342 
 1343     if (hbtype == TLS1_HB_REQUEST)
 1344      {
 1345      unsigned char *buffer, *bp;
 1346      int r;
 1347 
 1348      /* Allocate memory for the response, size is 1 byte
 1349       * message type, plus 2 bytes payload length, plus
 1350       * payload, plus padding
 1351       */
 1352      buffer = OPENSSL_malloc(1 + 2 + payload + padding);
 1353      bp = buffer;
 1354 
 1355      /* Enter response type, length and copy payload */
 1356      *bp++ = TLS1_HB_RESPONSE;
 1357      s2n(payload, bp);
 1358      memcpy(bp, pl, payload);
 1359      bp += payload;
 1360      /* Random padding */
 1361      RAND_pseudo_bytes(bp, padding);
 1362 
 1363      r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
 1364 
 1365      if (r >= 0 && s->msg_callback)
 1366       s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
 1367        buffer, 3 + payload + padding,
 1368        s, s->msg_callback_arg);
 1369 
 1370      OPENSSL_free(buffer);
```

### Exploitation:

Exploitation of this vulnerability was easy and is a good example of [CAPEC-540: Over-read Buffers](https://capec.mitre.org/data/definitions/540.html).
It was so simple that a cartoon, [XKCD #1354](https://xkcd.com/1354/], could clearly explain how to attack it.

Exploits merely needed to send a specially-crafted heartbeat request with a requested length with a small payload (e.g., 1 byte) and far longer payload length ()e.g., 65,535 bytes). The vulnerable server using OpenSSL, because it unwisely trusted the claimed length, would respond by copying the provided payload provided by many bytes from its memory containing unauthorized data, then send that response. Authentication was *not* required to trigger this vulnerability, as a heartbeat request did not require user authentication.

If that unauthorized data in the response was sensitive, the attacker would then receive that sensitive data. Unfortunately, because the memory is leaked from the heap region of memory, and was often data managed by OpenSSL, it often contained extremely sensitive data such as private keys, passwords, and so on.

In addition, the attack is silent, leaving no trace in standard logs. This made it an attack with a potentially high impact and low detectability.

### Fix:

Let's examine [commit 731f431497f463f3](https://github.com/openssl/openssl/commit/731f431497f463f3a2a97236fe0187b11c44aead) which fixed the Heartbleed vulnerability. We'll examine the "diff" (difference) from its previous commit. Line numbers shown are for the updated file.

In this version, we first check if the record will be long enough to
store *any* reply, and if not, the request will be silently discarded (lines 1338-1340; notice that lines that *had* been earlier are moved to lines 1341 and below, because this new check is occurring early in the function).
[RFC 6520 section 4](https://datatracker.ietf.org/doc/html/rfc6520) says that
"If the payload_length of a received HeartbeatMessage is too large,
the received HeartbeatMessage MUST be discarded silently".
Previously this wasn't checked.
Lines 1343-1344 in the new version first check that the payload isn't too large.
The rest of the lines accurately compute the `write_length` and use *that*
as the length to write.

```diff
fixed file: ssl/d1_both.c

 1325 int
 1326 dtls1_process_heartbeat(SSL *s)
 1327     {
 1328     unsigned char *p = &s->s3->rrec.data[0], *pl;
 1329     unsigned short hbtype;
 1330     unsigned int payload;
 1331     unsigned int padding = 16; /* Use minimum padding */
 1332 
-         /* Read type and payload length first */
-         hbtype = *p++;
-         n2s(p, payload);
-         pl = p;
-     
 1333     if (s->msg_callback)
 1334         s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
 1335             &s->s3->rrec.data[0], s->s3->rrec.length,
 1336             s, s->msg_callback_arg);
 1337 
+1338     /* Read type and payload length first */
+1339     if (1 + 2 + 16 > s->s3->rrec.length)
+1340         return 0; /* silently discard */
+1341     hbtype = *p++;
+1342     n2s(p, payload);
+1343     if (1 + 2 + payload + 16 > s->s3->rrec.length)
+1344         return 0; /* silently discard per RFC 6520 sec. 4 */
+1345     pl = p;
+1346
 1347     if (hbtype == TLS1_HB_REQUEST)
 1348         {
 1349         unsigned char *buffer, *bp;
+1350         unsigned int write_length = 1 /* heartbeat type */ +
+1351                         2 /* heartbeat length */ +
+1352                         payload + padding;
 1353         int r;
 1354 
+1355         if (write_length > SSL3_RT_MAX_PLAIN_LENGTH)
+1356             return 0;
+1357 
 1358         /* Allocate memory for the response, size is 1 byte
 1359          * message type, plus 2 bytes payload length, plus
 1360          * payload, plus padding
 1361          */
-1362         buffer = OPENSSL_malloc(1 + 2 + payload + padding);
+1362         buffer = OPENSSL_malloc(write_length);
 1363         bp = buffer;
 1364 
 1365         /* Enter response type, length and copy payload */
 1366         *bp++ = TLS1_HB_RESPONSE;
 1367         s2n(payload, bp);
 1368         memcpy(bp, pl, payload);
 1369         bp += payload;
 1370         /* Random padding */
 1371         RAND_pseudo_bytes(bp, padding);
 1372 
-1373         r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
+1373         r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, write_length);
 1374 
 1375         if (r >= 0 && s->msg_callback)
 1376             s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
-1377                 buffer, 3 + payload + padding,
+1377                 buffer, write_length,
 1378                 s, s->msg_callback_arg);
 1379 
 1380         OPENSSL_free(buffer);
```

### Prevention:

In this case, Google found the vulnerability through careful human review, while Codenomicon found the vulnerability through an advanced fuzzing technique carefully crafted to find subtle defects. However, Heartbleed was found after-the-fact. We want to find vulnerabilities *before* they are released.

As noted in [How to Prevent the next Heartbleed](https://dwheeler.com/essays/heartbleed.html), many static analysis tools had been used to analyze OpenSSL yet this vulnerability was not found by any of them. Typical static analysis tools use heuristics, and complex code often leads them to fail to detect vulnerabilities. Many dynamic test suites only have "positive tests" to verify that the program works correctly when given correct data, but in security, what usually matters is "negative tests" to verify that the program works correctly when given a data or request that is *not* correct.

Instead, that paper identified techniques that would have actually detected Heartbleed *before* it was deployed:

1. *Thorough negative testing in test cases (dynamic analysis).* Negative testing is creating tests that should cause failures (e.g., rejections) instead of successes. Thorough negative testing in test cases creates a set of tests that cover every type of input that should fail.
2. *Fuzzing with address checking and standard memory allocator (dynamic analysis).* Unfortunately traditional fuzz testing approaches were not helpful in this case. But there are simple lessons we can learn. Fuzzing would have been much more effective if a special tool called an address accessibility checker had also been used.
3. *Compiling with address checking and standard memory allocator (hybrid analysis).* This is really a damage reduction approach, instead of an approach that eliminates the problem. From a security point of view this approach turns a loss of confidentiality into a loss of availability. However, this would impose a significant loss of performance.
4. *Focused manual spotcheck requiring validation of every field (static analysis).* The vulnerable code was reviewed by a human, so merely having a single human reviewer was obviously not enough. However, a variation would have worked - requiring the human (manual) review to specifically check every field to ensure that every field was validated.
5. *Fuzzing with output examination (dynamic analysis).* Fuzz testing traditionally involves sending lots of input to a program and looking for grossly incorrect behavior such as crashes. In fuzzing with output examination, the fuzzing system also examines the target of evaluation (TOE) output, e.g., to determine if the output is expected, or if it has various anomalies that suggest vulnerabilities.
6. *Context-configured source code weakness analyzers, including annotation systems (static analysis).* Traditional source code weakness analyzers could not find Heartbleed, because they used general-purpose heuristics that simply didn’t work well enough in this case, in part because of the complexity of the code. It is always best simplify the code where you can, but there is always some minimal complexity based on what you are trying to accomplish.  Another approach is to use a source code weakness analyzer, but then provide far more information about the program that you are analyzing.
7. *Multi-implementation 100% branch coverage (hybrid analysis).* Another approach that would probably have detected Heartbleed is 100% branch coverage of alternative implementations. Branch testing cannot detect when input validation code is missing in a particular program. Branch coverage can, however, detect existing untested branches in a different implementation.
8. *Aggressive run-time assertions (dynamic analysis).* Software developers could aggressively insert and enable run-time assertions. There is speculation that this might have countered Heartbleed.
9. *Safer language (static analysis).* The underlying cause of Heartbleed is that the C programming language (used by OpenSSL) does not include any built-in detection or countermeasure for improper restriction of buffers (including buffer over-writes and over-reads). Almost all other programming languages automatically counter improper restriction.
10. *Complete static analyzer (static analysis).*  A complete (sound) static analyzer is designed to find all vulnerabilities of a given category. These analysis tools limit what constructs they can use, and developers typically have to limit their programs to work within those constructs and/or provide additional annotations to provide additional information the tool needs. 
11. *Thorough human review / audit (static analysis).* A thorough independent human review of software, specifically focused on ensuring security and finding vulnerabilities, is typically an excellent way to find vulnerabilities. These reviews, aka an audit, should presume the software is vulnerable until shown otherwise.
12. *Formal methods (static analysis).*  Formal methods involve the use of “mathematically rigorous techniques and tools for the specification, design and verification of software and hardware systems”. These can prove implementations are correct (given certain assumptions) but are expensive and challenging to scale up.

Other actions could reduce the risk of vulnerabilities like Heartbleed:

1. *Simplify the code.* Emphasizing simpler code that is *obviously right* tends to reduce vulnerabilities in general. Static analysis tools struggle and eventually fail on more complex code. Humans do, too. After Heartbleed the OpenSSL project worked to reduce the complexity of its codebase, which overall reduces the likelihood of such vulnerabilities.
2. *Simplify the Application Program Interface (API).* APIs are often absurdly complex or difficult to use, leading to complex and hard-to-understand code.
3. *Allocate and deallocate memory normally.* OpenSSL had a complex approach to memory management that somewhat impeded analysis.
4. *Use a standard FLOSS license.* OpenSSL at the time used an odd one-off license. This non-standard licensing approach discouraged review since few people (or lawyers) want to analyze or deal with an odd unknown license. This lack of review likely contributed to failure to detect the vulnerability before release. Newer versions of OpenSSL use the Apache 2.0 license, a far more common license.

### References:

* Wheeler, David A. "How to Prevent the next Heartbleed." (2014). <https://dwheeler.com/essays/heartbleed.html>
* MITRE. "CVE-2014-0160." <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160>
* MITRE. "CWE-126: Buffer Over-read." <https://cwe.mitre.org/data/definitions/126.html>
* MITRE. "CAPEC-540: Over-read Buffers." <https://capec.mitre.org/data/definitions/540.html>
* Seggelmann, R., et al. "RFC 6520: Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension." (2012). <https://tools.ietf.org/html/rfc6520>
* Codenomicon. "The Heartbleed Bug." <https://www.heartbleed.com/>
* OpenSSL. Heartbleed commit diff. <https://github.com/openssl/openssl/commit/731f431497f463f3a2a97236fe0187b11c44aead>

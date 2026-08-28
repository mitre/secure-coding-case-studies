Path as a vulnerability in Apache HTTP Server

NAME: Charan Anish Kogila
G-num: G-01545376
Gmail: ckogila@gmu.edu
Net-Id: ckogila
Introduction
Path vulnerability susceptibility Path vulnerabilities can arise because the program allows attackers to travel outside the limited directory and access the unintended fileship when it fails to properly validate or normalize user controlled filesystem paths. CWE-22 and CWE-23 are listed as these issues, and they are invariably on the CWE Top 25 Most Dangerous Software Weaknesses list. Apache HTTP Server which is one of the most widely used web server on the Internet is based on proper processing of paths to ensure limits on accessing files. CVE-2021-41773 is discussed in this case study, the flaw is described by the vulnerable code of the program, the how the vulnerability was exploited is shown, and the Apache fix to resolve the vulnerability is shown.
Software
Name: Apache HTTP Server
Language: C
URL: https://github.com/apache/httpd
Weakness: 
CWE-22: An Exchange of a Pathname with a Restricted Directory.
CWE-23: Relative Path Traversal
A weakness found in the construction of filesystem paths is path traversal weaknesses When software is compiled with unverified input, path traversal weakness may occur due to its failure to safely normalize and validate an input. Attackers can provide it with sequences like ../ or coded versions so as to get out of the desired directory and access confidential files. Canonicalization issues arise because a program will check one path and then transform it to the canonical form which is the normalized form. When a sanitization is performed along some non-canonical path, an attacker may produce an input that would seem innocuous at the time the renewal is performed, but would collapse to an insecure destination after the normalization is done.
One of the most common coding errors is to combine a trusted base directory and untrusted user input and apply inadequate checks:
char userpath = getinput();
snprintf(full, READ TO 100); within ourselves, Okay, chord截到 100, of one subject on place, pro-snprintf(full, sizeof(full), factor / b co-ro建, capacity of base Between b and l);<|human|>snprintf(full,sizeof(full), base/userpath); OF suchrattfixto n

When the userpath includes ../../, the out resultant path might get out of the limited guardian folder. Unless canonized correctly, i.e. sorted with symbolic connections, dot-segments removed, and encoded characters decoded, the application can unknowingly give access to any location in the filesystem.
Vulnerability:
CVE-2021-41773
This was a vulnerability in Apache HTTP Server 2.4.49 which was due to the modifications in the logic of path normalization made added in a refactoring patch. The server tried to make things simpler by the way it combined request URIs with the DocumentRoot, however, the new logic did not adequately canonicalise paths in advance of applying authorisation rules. A consequence of this was that the attacker might exploit specially engineered traversal sequences -em is especially - to extract arbitrary files by working outside the DocumentRoot.
The bug was found in the basic request translation unit, which is mostly in server/core.c, the URI-to-filepath normalization unit. Canonicalization was not done before path checks and encoded traversal sequences like percent2epercent2epercent2fterm were not completely repudiated.
Vulnerable Code Snippet Vulnerable Code Snippet ( Apache 2.4.49 - server/core.c ).
insecure file web technology vulnerable (Apache HTTP Server 2.4.49):server/core.c: ...
crypto-economic system: Attempt to simplify the process of path merging.
rv = aprfilepathmergeresume Program Name<|human|>rv = aprfilepathmerge aprfilepathmergeInitial set of Program Nameuri uri docroot aprfilepathreplaceipal
                        APRFILEPATHNOTABSOLUTE, r->pool);
Checking authorization using the path that is not normalized /
if (APRSUCCESS == rv) {
    apdirectorywalk(r) gives accessstatus;
}
...
Normalization step is too late in coming with coded traversal omitted /.
apnormalizepath(&r->filename, r->pool);
...
What Is Wrong( Line-by-Line Explanation).
Apache tries to combine DocumentRoot with r->uri with aprfilepathmerge, however it does not provide enough flags (APRFILEPATHNOTABSOLUTE), which makes it possible to survive with the encoded traversal elements.
It is then called apdirectorywalk() prior to full canonicalization of the path, that is, giving permission checks on a path that seems to be safe.
Apache makes subsequent calls to apnormalizepath after these checks, which is later than it is necessary to ensure that the non-target directory is accessed.
Traversal sequences like the 62e62f (6) used to encode the ../ sequence are bypassed by early filtering since after access decisions, the decoding and normalization is done.
The consequence is the reachability path weakness.
Exploit:
CAPEC-126: Path Traversal
The attacker might use this vulnerability to send formatted HTTP requests with coded dot-segments. Since Apache verified the non-canonical trail, and not normalized that, it is only later that normalization takes place, paths like:.%2e/%2e%2e/leaked out of the DocumentRoot of the server.
One of the common exploits appeared as follows:
GET /.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: vulnerable.example.com
When processed by Apache 2.4.49:
The server assumed the path to be a DocumentRoot.
Checks on authorization met successfully.
Canonicalization was done after checking and its path set to /etc/Passwd is resolved.
The attacker was provided with /etc/passwd.
Real-World Impact
In September-October 2021, the attackers managed to:
Accessed /etc/passwd and other OS confidential files.
Secret files accessed on the server through.htaccess or configuration.
Achieved remote code execution (in case CGI or modcgi was turned on) by running the scripts the user did not want to run.
Several days after the vulnerability was announced, it was actively abused in the wild.
Fix:
Apache corrected the bug with 2.4.50 (and improved the fix in 2.4.51). The patch engaged in pre-checking strict canonicalization and also refused to accept encoded traversal sequences and made sure that authorization was done after full normalization was completed.
Relevant Block offixed code (server/store.c) / fixed file: server/core.c /code obsolete and traversable / rv = aprfilepathmergeresume Program Name<|human|>rv = aprfilepathmerge aprfilepathmergeInitial set of Program Nameuri uri docroot aprfilepathreplaceipal
APRFILEPATHNOTABSOLUTE, r->pool);
if (APRSUCCESS == rv) {
apdirectorywalk(r) gives accessstatus;
}
canonicalization / more severe and new code.
rv = aprfilepathmerge(newpath, docroot, ruri,–)
APRFILEPATHTRUENAME, r->pool);
if (rv != APRSUCCESS) {
return HTTPFORBIDDEN;
}
authorization is now performed after full normalization */
r->filename = newpath;
apdirectorywalk(r) gives accessstatus;

Line-by-Line Explanation:
APRFILEPATHTRUENAME causes canonicalization principles to be followed and eliminates dot-segments and symbolic linkages.
In case of a failure of canonicalization or on an unsafe path the request will be rejected with HTTPFORBIDDEN.
To enable the permission (apdirectorywalk) to run, the end-path of the filesystem must have been completely normalized.
This ensures that previously checked sequences do not traverse sequences that have been encoded or left in their raw form.

Prevention:
The developers are advised to perform systematic secure coding to prevent such vulnerabilities as path traversal, such as CVE-2021-41773: Canonicalize and Check Permissions Going on Before Checking Where To Write. Full normalization of paths should always be done, status: symbolic links should be resolved, dot-segments should be removed, encodings should be decoded, and then authorization should be performed.
Canonical Path APIs Use Trusted OS Canonical Path APIs.
Canonicalization is implemented automatically through functions, which minimize the possible errors of custom logic.
Discover in the Early Cases Reject Encoded Traversal Sequences.
Reject entry of user input with coded in it: %2e (.) %2f (/) %5c ()
Encodings that traumatize to character mixing UTF-8
Violate Not Only Allow-List Directory Constraints.
Make sure that all the files requested should be under a specified root folder. The person has been canonized; check: in case non startswith (realpath,docroot) reject; Path Traversal Regression Tests.
Includes automated tests which attempt:  ../ ..%2f .%2e/
Traversal sequences placed in unicodes.
Do a deal against Refactoring Security-Critical Logic Without Tests.
CVE-2021-41773 came about due to a refactoring mistake. Unit and full integration tests have to protect large code changes to path-handling logic.
Path-Handling Foss-Scale to Path-Handling Code.
Normalization functions and filepath parsers are good subjects to fuzz testing and would have probably identified the defect prior to the release.
Information Disclosure: read /etc/passwd, read /etc/shadow, read server-configuration files, read applications source code, read database credentials and read private keys.
System Reconnaissance: Scanned internal files system to determine more attack vectors.
Remote Code Execution: On systems which support CGI scripts or modcgi, the attacker accessed executable scripts or uploaded malicious code to executable directories resulting in complete system compromise.
This was a very high vulnerability as there did not need any authentication, it impacted default settings, and could be used with straightforward HTTP requests. Thousands of servers were affected in the matter of several days or so and it was assessed by CVSS rating that equals to high severity (7.5).
Fix:
Apache also responded with urgency releases out of 2.4.50 (first fix to CVE-2021-41773) and 2.4.51 (full fix following a discovery of a bypass). Those changes all centered on defining the core fixes that introduced three essential changes: the use of extensive path normalization decoding all percent-encoded characters then validating them, refuting client-supplied encoded traversal sequences specifically, and sequence rearrangement to ensure all security checks were performed after the entire canonicalization had been performed.
The corresponding improvements in server/core.c were: diff/ Fixed file server/core.c ( Apache HTTP Server 2.4.50+) server/core.c / Apnormalizepath(char path, unsigned int flags) apdeclare(int) apnormalizepath.
 {
Old Unreserved characters / are only decoded.
in case (flags APNORMALIZEDECODEUNRESERVED)
decodeunreserved(path);
}
matter of incidence, combination, environment, innovation, and adjustment), a uniform wired infrastructure standard under IPv6 became necessary.<|human|> Breaking Decode ALL numbers encoded as percentages on the first pass Decode Finally, with IPv6 a reasonably standardized wired infrastructure became a necessity.
in case (flags[1] APNORMALIZEDECODEALL)
apunescapeurlkeep2f(path, 0);
}
unit Only Sweet unit is one labeled with an encoded dot, a unit.
if (strstr(path, "%2e")    strstr(path, "%2E")) {
return HTTPFORBIDDEN;
}
 Avoiding the issue when it could err will require some prior classifications that the current coremaptostorage accepts as correct.<|human|>contravenedian Staying where it might go wrong will entail certain classifications that the existing coremaptostorage finds correct.
 {
Normalization and restricted decoding: Old.
apnormalizepath(path, APNORMALIZEDECODEUNRESERVED);
Option: Break Open Before full canonicalization Old: Check aliases before full canonicalization Old: Check aliases before full canonicalization
in case (checkaliasesandredirects(r, path) is to be motley):
return OK;
}
New: Total decoding out of all those that are normalised.
in case (apnormalizepath(path, APNORMALIZEDECODEALL) is not OK)
return HTTPFORBIDDEN;
}

     Sanity check build canonical file path Consistently build canonical file path Warning Consistently build canonical file path sanitized Build canonical file path Warning Consistently build canonical file path sanitized Build canonical file path Conditional Consistently build canonical file path Conditional sanitized Build canonical file path Clean Build canonical file path Clean Build canonical file path sanitized Build canonical file path Consistently
rv = aprfilepathmerge—also used to mean: merge AVPRivMerge
|human|>rv = aprfilepathmerge(1)(&path, docroot, r URI); 
APRFILEPATHNOTABOVEROOT, r->pool);
rv = aprfilepathmerge—also used to mean: merge AVPRivMerge
|human|>rv = aprfilepathmerge(1)(&path, docroot, r URI);
APRFILEPATHNOTABOVEROOT   
APRFILEPATHSECUREROOTTEST  
APRFILEPATHNOTRELATIVE, r->pool);
if (rv != APRSUCCESS) {
The function aplogrerror(APLOGMARK, APLOGERR, rv, r,) returns the value of the variable r divided by the value of the variable rv.<|human|>The function aplogrerror(APLOGMARK, APLOGERR, rv, r, ) is a function that gives the value of a variable r divided by the value of a variable rv.
"The attempt to understand the path was detected;
return HTTPFORBIDDEN;
}
New: Authorization is to be done after canonicalization /
in case (checkaliasesandredirects(r, path) is to be motley):
return OK;
}
     ...
 }
There are the following key enhancements:
Complete Decoding: 
APNORMALIZEDECODEALL flag will guarantee that all the percent characters are decoded (even the special characters of the form of percent 2e and percent 2f) and no validation is handled. This rules out the bypass technique.
Explicit Rejection: 
The code has now been updated to explicitly check or check encoded dot-outcodes, at once, rather than relying on normalization to do so, serve up HTTPFORBIDDEN as a defense-in-depth defense even in the event of breakdown in this verification.
Improved Canonicalization Flags: There is added aprflagmerge which uses more security flags:
APRFILEPATHSECUREROOTTEST: Conducts extra when it comes to security checks.
APRFILEPATHNOTRELATIVE:versionspath path component is denied.
These flags are used along with APRFILEPATHNOTABOVEROOT to disable transmissions.
Reordered Checks: 
The checks on authorization and alias are now performed after canonicalization and path merging is completed and the security decision is made on the actual filesystem path and not the request URI that may have been deceived.
Improved logging: Failed paths operations are logged out with details, allowing of security monitoring and responding to an incident.
These modifications will make the intention to cross that of the DocumentRoot be detected and rejected before the request can be handed over to file access, removing the vulnerability at numerous defensive levels.
Prevention:
Avoiding path traversals vulnerabilities implies that there should be a systematic secure coding practice in the software development lifecycle. Based on the Apache CVE-2021-41773 case, the following are practical recommendations applicable to the developers:
Canonicalize Pre Canonicalization.
Any path, when subjected to any security checks, should always be converted into its canonical form. Call archive canonicalization functions proffered by the operating system such as in POSIX realpath or in Windows GetFullPathName. The functions sort out symbolic links, eliminate redundant separators and strip out the use of .. sequences to give the real filesystem path.
cchar canonical[PATHMAX];
in case (realpath(userpath, canonical) is not in the form of realpath) this is not true.
    return ERRORINVALIDPATH;
}

# canonical path security check NOW perform security checks on canonical path
] cannot be given to a group alias and must be considered a client, i.e., cannot be trusted by this group.<|human|>] cannot be passed to a group alias, and must be treated as a client, i.e. not to be relied on by this group.
    return ERRORACCESSDENIED;
}
The Apache vulnerability was exactly due to the fact that the checks came before full canonicalization had been carried out. The code of path validation never should be trusted to perform on non-canonical input.
Early Decode All Encoding Schemes.
There may be multiple levels of encoding in HTTP requests (percent encoding, and variant of UTF-8, twice encoding). All encoded diverse characters are to be decoded then validated. Develop an all-encompassing decoding feature that would deal with:

Standard percent-encodingPath max-flag goal target-ratio
 within range max-ratio target-ratio objective-ratio range of intentions goal-ratio goals ratio x
|human|>Standard percent-encoding (%XX)
Encoding variants of unicodes.
Incidents of double and triple encoding ( -3).
Mixed case encodings (%2E vs %2e)

Once it has been decoded, explicitly whatsoever you come upon forms of dangerous characters, and the two main characters are dots and slashes, which are explicitly rejected.
Use Allowlist Validation
No attempt at blocking dangerous patterns (a blacklist solution which attackers often evade) is made, but what is allowed is defined and nothing be rejected. For file access operations:
const|human|>const|human|>Find out permitted file extensions.
const char permittedextensions[s] = {.html, .css, .js, .jpg, NULL
Works well with images, and any other type of data people would find useful as a bookmark.<|human|>const char permittedextensions[s] = {.html, .css, .js, .jpg, NULL);
Condition Handle This is also referred to as file extension validation.<|human|>Condition Check This can also be called file extension validation.
Additional Data bool extensionallowed = false;
; int i= 0; (allowedextensions[i]is not a null)
    in case of (endswith(canonicalpath, authorized extensions[i])
        extensionallowed = true;
        break;
    }
}
// Check path removes in authorized directory as well.
in case there is no extensionallowed Extension without extensionpathwithinroot canonicalpath, docroot) {
    return ERRORACCESSDENIED;
}
This strategy will ensure that the security policy is clear and limits the attack surface.
Implement Defense in Depth
Put many layers of protection in place and in case one layer succeeds, the other ones put up the attack:
Input justification: Early rejection of the suspicious characters.
Normalization To code as normal: Decode all encoding schemes.
Canonicalization: Absolute paths to paths.
Check permissions Authorization: Check permissions.
File sanity checks: Check of path OS level.
Control: Track suspicious path numbers.
The fix by Apache added some of these layers and thus the attack would not even pass through in case the normalization was bypassed and an explicit check on the presence of the word %2e was checked.
Automate Security Testing
The vulnerabilities experienced in path traversal frequently recur in the course of refactoring. require the use of automated regression tests:
c// Example test cases
testpathtraversal("../../../etc/passwd", EXPECTREJECT);
testpathtraversal("..%2f..%2f..%2fetc%2fpasswd", EXPECTREJECT);
testpathtraversal(".%2e/%2e%2e/etc/passwd", EXPECTREJECT);
testpathtraversal("valid/file.html", EXPECT_ALLOW);
These tests have to be continuously run as the continuous integration pipelines to identify regressions prior to the deployment. Code refactoring has presented the Apache vulnerability, which would have been immediately revealed through automated tests.
Path Handling Codes Path Handling Codes connected to Fuzzing Code.
Test path validation functions by using fuzzing software such as AFL++ or libFuzzer and test with millions of malformed inputs. They identify edge cases not found by their manual analysis:
c fuzzing target Fleetwood, path validation/target.
LLVMFuzzerTestOneInput int LLVMFuzzerTestOneInput(const uint8t data, sizet size) {
    char path[4096];
    if (size >= sizeof(path)) return 0;
    memcpy(path, data, size);
    path[size] = '\0';
    // Test whether path validation is safe on arbitrary input.
    validateandcanonicalizepath(path);
    return 0;
}
Embark on Fuzzing - Fuzzing protects systems by testing their security-important code continuously by assigning CPU cycles to this task.
Check Changes with Critical Security Changes.
Alterations to the code in authentication, authorization or code in path handling involve a greater level of scrutiny. The Apache vulnerability was the result of good-minded refactoring. Establish processes where:
Security team members need to review security critical modules.
Threat models are also updated with changes in the threat model explaining the security implications.
Along with refactoring, there is an improved test coverage.
Changes in security barriers are indicated by automated mechanisms of brain analysis.
Use Secure API Wrappers
Design API wrappers API wrappers that are high-level and trap secure path handling so that developers find it easy to do the right thing:
c// Secure wrapper function
int securefileopen(constchar basedir, constchar userpath, 
                     FILE outfile) {
    char canonical[PATHMAX];
    char fullpath[PATHMAX];

    // Decode and canonicalize
    decodeallencoding(userpath, fullpath);
    when ( fullpath, canonical) is not realpath) = {lessen
        return ERRORINVALIDPATH;
    }
    checkbasečnívehicle /etc/base directory Check the base directory.
    i f strncmp(canonical, basedir,cached length basedir) 0.
        log Francisco security event Traversal attempt, canonical;
        return ERRORACCESSDENIED;
    }
    outfile = fopen(canonical, "r");
    return (*outfile != NULL) ? SUCCESS : ERROROPENFAILED;
}
This is a wrapper that developers use besides building the paths manually, which minimize the chances of creating vulnerabilities.
Observes and acts on Red flags.
Implement production runtime monitoring, which will identify traffic trying to pass through it:
Notification of recurring denied connection requests on the same source.
Suspicious clients should be rate limited.
Transmit security logs in SIEM systems to get correlated with.
The rapid response to the Apache CVE-2021-41773 wave of exploitations was possible due to their early identification, and administrators either patched their systems or deployed WAF rules prior to loss of control.
Enforce Security Consciousness.
Lastly, make paths awareness through development teams through:
Consistent security education with real life scenarios such as CVE-2021-41773.
Path handling checklists Code review checklists.
File access feature threat modeling.
Analyzing postmortem in case of vulnerabilities being discovered.
The attention to the security-conscious engineering culture has been proved by the timely reaction and full-scale fixes of the Apache HTTP Server team.
Conclusion:
CVE-2021-41773 is a recent chilling example of how a minor update to a piece of security-sensitive code can add serious vulnerability even to software with many years of history of active use and a team of highly knowledgeable security researchers. The vulnerability allowed unauthenticated attackers access to arbitrary files on vulnerable servers causing massive information disclosure and, in certain settings, remote code execution. The underlying cause was unfinished path normalization that simply gagged all percent-encoded characters and the synchronization of authorization checks, ultimately, a typical violation of the tenets of an occurrence of safe coding.
The reaction of Apache although taking several rounds of patches, finally put in place a strong defense-in-depth measure. Best practices are exhibited in the fixes: all the characters of the encoding are properly decoded, all the suspicion patterns identified and recalled, and the OS-supplied canonical path APIs are used with suitable security flags, and security checks are performed in a recombined order, so that they only act on canonical paths. The changes caused by these changes have made the vulnerability to be nonexistent at several levels so that in case one of the protective measures are compromised, others can help avoid exploitation.
The wider implications on software developers are obvious: path traversal vulnerabilities are not going to disappear as they are caused by their inherent failures in the reasoning that developers apply to the paths and filesystems attempt to implement. In its prevention, strict implementation of canonicalization prior to validation, allowlist-based access control, defense in depth, automated testing with explicit consideration of traversal patterns, code review oriented towards security concerns in any modifications to path handling logic are all necessary. Developers can remove whole categories of path traversal vulnerabilities of their applications by learning about attacks such as CVE-2021-41773 and implementing systematically secure practices that encourage developers to eliminate all cases of this particular common and severe attack.
References:
Apache HTTP Server Project: 
https://github.com/apache/httpd
CVE-2021-41773 Record: 
https://www.cve.org/CVERecord?id=CVE-2021-41773
CWE-22: Pathname Missing Limitations: to a Restricted Directory.:
https://cwe.mitre.org/data/definitions/22.html
CWE-23: Relative Path Traversal:
https://cwe.mitre.org/data/definitions/23.html
CAPEC-126: Path Traversal:
https://capec.mitre.org/data/definitions/126.html
Microsoft - National Vulnerability database CVE-2021-41773:
https://nvd.nist.gov/vuln/detail/CVE-2021-41773
Apache HTTP Server 2.4.50 Changes:
https://downloads.apache.org/httpd/CHANGES2.4.50
Security fix Apache HTTP Server 2.4.51:
https://httpd.apache.org/security/vulnerabilities24.html
GitHub Commit - CVE-2021-41773 Fix:
https://github.com/apache/httpd/commit/e150697cc6d1bf2b9bcf8ca18b6a9078ad96f695
Apache Security Advisory:
https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773

Contributions
Originally created by Charan Anish Kogila 



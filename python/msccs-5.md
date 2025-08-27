# MSCCS-5 :: IMPROPER CERTIFICATE VALIDATION IN AIRFLOW

### Introduction:

Establishing a secure communications channel (often via the SSL/TLS protocols) typically involves using a digital certificate to authenticate identity and to establish an encrypted link. Establishing this secure context is essential to provide protection against malicious hosts that seek to impersonate their target. Failure to validate the digital certificate provided by a host creates a false root of trust in the communications channel thus removing the guarantee that potentially sensitive data is being sent to the intended endpoint securely. In 2023 such a vulnerability was disclosed in the Python-based Apache Airflow application. This case study looks at that vulnerability, the root cause authentication mistake, what it allowed an adversary to achieve, and how the code was eventually corrected.

### Software:

**Name:** Apache Airflow  
**Language:** Python  
**URL:** https://github.com/apache/airflow

### Weakness:

<a href="https://cwe.mitre.org/data/definitions/295.html">CWE-295: Improper Certificate Validation</a>

The weakness “Improper Certificate Validation” exists when an application either fails to validate, or incorrectly validates, a digital certificate. An adversary can take advantage of this weakness to impersonate an endpoint or perform an adversary-in-the-middle (i.e., man-in-the-middle) attack to intercept communications.

### Vulnerability:

<a href="https://www.cve.org/CVERecord?id=CVE-2023-41885">CVE-2023-41885</a> – Published 23 August 2023

The vulnerable code is part of the _build_client() method defined on line 80 of the imap.py file. This function determines the desired type of client connection and then configures the mail_client in the appropriate way. The provided input is parsed on line 82 to determine if the “use_ssl” flag is set to True. If True then on line 83 the client IMAP object gets assigned the IMAP4_SSL class. This IMAP object is then used on lines 88 and 90 to create the mail_client, which is returned from the function on line 92.

    vulnerable file: airflow/providers/imap/hooks/imap.py
    
    80	def _build_client(self, conn: Connection) -> imaplib.IMAP4_SSL | imaplib.IMAP4:
    81		IMAP: type[imaplib.IMAP4_SSL] | type[imaplib.IMAP4]
    82		if conn.extra_dejson.get("use_ssl", True):
    83			IMAP = imaplib.IMAP4_SSL
    84		else:
    85			IMAP = imaplib.IMAP4
    86
    87		if conn.port:
    88			mail_client = IMAP(conn.host, conn.port)
    89		else:
    90			mail_client = IMAP(conn.host)
    91
    92		return mail_client

The IMAP4_SSL class allows an optional ssl_context parameter that holds the configuration options, certificates, and private keys for the secure connection. However, as seen on lines 88 and 90, no ssl_context is passed to the constructor of this class and thus the ssl_context defaults to the value of “None”. The lack of a defined ssl_context means that the certificate is trusted by default and is not checked for validity or possible revocation. The connection host will blindly trust the host it has connected to.

### Exploit:

<a href="https://capec.mitre.org/data/definitions/94.html">CAPEC-94: Adversary in the Middle</a>

An adversary could take advantage of this by inserting itself into the communications channel path and providing its own malicious certificate. The malicious host will present a certificate to the connection host that if not properly validated will enable the malicious host to be perceived as legitimate.

Inadequate verification of this malicious host’s identity would permit the adversary to perform a wide array of actions. The adversary may opt to filter selected traffic, modify selected traffic before passing it along to the intended host, or passively record all traffic from this application.

### Fix:

To address this issue, the code was modified to set one of two ssl_context options whenever the “use_ssl” flag is set to True. The suggested “default” option uses the create_default_context() method to create a new SSL context which will load the system’s trusted CA certificates, enable certificate validation and hostname checking, and try to choose reasonably secure protocol and cipher settings.

    fixed file: airflow/providers/imap/hooks/imap.py
    
    81		def _build_client(self, conn: Connection) -> imaplib.IMAP4_SSL | imaplib.IMAP4:
    82			mail_client: imaplib.IMAP4_SSL | imaplib.IMAP4
    83			use_ssl = conn.extra_dejson.get("use_ssl", True)
    84			if use_ssl:
    85				from airflow.configuration import conf
    86
    87				ssl_context_string = conf.get("imap", "SSL_CONTEXT", fallback=None)
    88				if ssl_context_string is None:
    89					ssl_context_string = conf.get("email", "SSL_CONTEXT", fallback=None)
    90				if ssl_context_string is None:
    91					ssl_context_string = "default"
    92				if ssl_context_string == "default":
    93					ssl_context = ssl.create_default_context()
    94				elif ssl_context_string == "none":
    95					ssl_context = None
    96				else:
    97					raise RuntimeError(
    98						f"The email.ssl_context configuration variable must "
    99						f"be set to 'default' or 'none' and is '{ssl_context_string}'."
    100				)
    101			if conn.port:
    102				mail_client = imaplib.IMAP4_SSL(conn.host, conn.port, ssl_context=ssl_context)
    103			else:
    104				mail_client = imaplib.IMAP4_SSL(conn.host, ssl_context=ssl_context)
    105		else:
    …
    111		return mail_client

The fixed code performs a series of logic checks to determine which option (default or none) is desired. The Airflow support documents clarify the two SSL_CONTEXT options by stating that "default" sets the code to call “ssl.create_default_context()” which requires that certificates in the operating system are updated and that SMTP/IMAP servers have valid certificates that have corresponding public keys installed on the machines. The second SSL_CONTEXT option is "none" which disables checking of the certificates for testing. It is not recommended for operations as it allows adversary-in-the-middle attacks if the infrastructure is not sufficiently secured.

Lines 87-92 of the fixed code check if the SSL_CONTEXT configuration in either imap or email has set as “default”, or if both configurations have not been set and are empty. In these situations the function create_default_context() is then called on line 93. The ssl.create_default_context() function call with no parameters passed in creates an environment in the default secure state and establishes the web server authentication via the highest compatible secure protocol for the client and host.

The option “none” will only be set in the code if the imap configuration is specifically set to “none”, or if the imap configuration is empty and the email configuration is set to “none”.

### Conclusion:

The changes force the default secure approach to hostname validation when using SSL. The addition of the ssl_context mitigates the root cause authentication weakness “Improper Certificate Validation” by forcing the installed CA certificate to be used to establish a secure communications channel between the mail client and trusted host. Adversaries are no longer able to impersonate the trusted host and intercept secure emails.

### References:

Apache Airflow Project Page: https://airflow.apache.org/

CVE-2023-41885 Entry: https://www.cve.org/CVERecord?id=CVE-2023-41885

CWE-295 Entry: https://cwe.mitre.org/data/definitions/295.html

CAPEC-94 Entry: https://capec.mitre.org/data/definitions/94.html

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-5f35-pq34-c87q

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2023-39441

Apache Airflow Code Commit to Fix Issue: https://github.com/apache/airflow/pull/33108/commits/b20d631598af7e874fa40c26e8d6868960077ea9

Python Documentation for IMAP4_SSL(): https://docs.python.org/3/library/imaplib.html#imaplib.IMAP4_SSL

### Contributions:

Originally created by David Rothenberg - The MITRE Corporation<br>
Reviewed by Drew Buttner - The MITRE Corporation<br>
Reviewed by Steve Christey - The MITRE Corporation

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a>

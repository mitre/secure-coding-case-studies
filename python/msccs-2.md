# MSCCS-2 :: OPEN REDIRECT IN JUPYTER SERVER

**Introduction:** The redirection of an HTTP based web application to an adversary-controlled URL (also known as “Open Redirect”) is a dangerous condition that can lead to a successful phishing attack. This type of attack is one of the most common methods of exploitation and can result in a variety of devastating consequences including the installation of malware and stolen credentials. In 2023 such a vulnerability was disclosed in the Python-based Jupyter Server. This case study looks at that vulnerability, the root cause input validation mistake, what it allowed an adversary to achieve, and how the code was eventually corrected.

**Language:** Python  
**Software:** Jupyter Server  
**URL:** https://github.com/jupyter-server/jupyter_server

**Weakness:** CWE-601: URL Redirection to Untrusted Site

The weakness exists when an application accepts a user-controlled input and then uses that input to craft a URL that the application leverages during a redirect. Such a redirect is common when a web application finishes a task or needs to change course based on some event. Unfortunately, leveraging externally influenced input enables an adversary to trick a user into being redirected to a malicious location. In this specific case the “Improper Validation of Syntactic Correctness of Input” (i.e., CWE-1286) provided such an opportunity.

**Vulnerability:** CVE-2023-39968 – Published 29 August 2023
The URL redirection issue occurs in the login.py file within Jupyter Server when the vulnerable source code fails to neutralize certain values obtained from the user and then passes the resulting URL to the redirect() method on line 61.

    vulnerable file: jupyter_server/auth/login.py
    
    31	def _redirect_safe(self, url, default=None):
    …
    38		if default is None:
    39			default = self.base_url
    …
    44		parsed = urlparse(url)
    45		if parsed.netloc or not (parsed.path + "/").startswith(self.base_url):
    46			# require that next_url be absolute path within our path
    47			allow = False
    48			# OR pass our cross-origin check
    49			if parsed.netloc:
    50				# if full URL, run our cross-origin check:
    51				origin = f"{parsed.scheme}://{parsed.netloc}"
    52				origin = origin.lower()
    53				if self.allow_origin:
    54					allow = self.allow_origin == origin
    55				elif self.allow_origin_pat:
    56					allow = bool(re.match(self.allow_origin_pat, origin))
    57			if not allow:
    58				# not allowed, use default
    59				self.log.warning("Not allowing login redirect to %r" % url)
    60				url = default
    61		self.redirect(url)
  
To be vulnerable, two conditions must be met. First, the string “url” must be controllable by an adversary such that they can point the redirect to a location of their choosing. Second, the code must incorrectly neutralize (e.g., canonicalize, encode, escape, quote, validate) the adversary provided input such that the target location is not rejected.

*ADVERSARY CONTROLLED INPUT*

Exploring the first condition, the weakness in the code relies on the fact that string “url” is tainted (i.e., user controlled). Line 31 shows the _redirect_safe() method definition where the string “url” is passed in. This string comes from lines 79 and 94 of the same file (see listing below) where it is received directly from GET and POST requests that an adversary can manipulate and issue. The tainted URL values are passed into _redirect_safe() on lines 80 and 95 respectfully.

    supporting file: jupyter_server/auth/login.py
    
    76	def get(self):
    77		"""Get the login form."""
    78		if self.current_user:
    79			next_url = self.get_argument('next', default=self.base_url)
    80			self._redirect_safe(next_url)
    81		else:
    82			self._render()
    83
    84	def post(self):
    85		"""Post a login."""
    86		user = self.current_user = self.identity_provider.process_login_form(self)
    87		if user is None:
    88			self.set_status(401)
    89			self._render(message={"error": "Invalid credentials"})
    90			return
    91
    92		self.log.info(f"User {user.username} logged in.")
    93		self.identity_provider.set_login_cookie(self, user)
    94		next_url = self.get_argument('next', default=self.base_url)
    95		self._redirect_safe(next_url)

Both the get() and post() functions are Jupyter Server implementations of the hooks provided within the Tornado web framework that is being leveraged. For additional details about this, consult the Tornado documentation cited in the Reference section.

*INCORRECT NEUTRALIZATION*

For the second condition, the neutralization of the provided URL is incorrect. Line 44 of the vulnerable code uses the Python urlparse() method to split the tainted string “url” into its components. These components correspond to the general URL structure for HTTP:

    <scheme>://<netloc>/<path>?<query>#fragment
    
    https://www.example.org/our-impact?next=company-goals#first
    
    scheme = https
    netloc = www.example.org
    path = /our-impact
    query = next=company-goals
    fragment = first

Referring to the Internet Engineering Task Force (IETF) RFC1738 that defines Uniform Resource Locators (URL), the netloc component, also referred to as the host, can be left blank, specifically as part of the file scheme. Section 3.10 further explains this:

    As a special case, <host> can be the string "localhost" or the empty string; this is interpreted as 'the machine from which the URL is being interpreted'.

The Python urlparse() function specifically states that it does not perform validation of the provided URL, focusing instead on splitting the URL string into its components.

The specific case to explore is that of a missing netloc. Consider a URL with the form `scheme:///path`. Note the three slash characters. This might result from a user that mistakenly adds a third slash resulting in a URL like `https:///www.example.org/our-impact`. The urlparse() function follows the IETF RFC1738 specification and assumes the netloc is empty. It returns the following components from the example:

    scheme = https
    netloc=''
    path='/www.example.org/our-impact'

Contrary to the IETF RFC1738 specification, some web browsers attempt to silently solve the oddity by ignoring what appears to be a mistakenly added extra slash. A browser may interpret the example URL with the extra slash as:

    scheme = https
    netloc = www.example.org
    path = /our-impact
  
Turning our attention back to the vulnerable source code, the jupyter_server code on lines 45-60 attempts to check that the provided URL is a location within the allowed origin (an allowed scheme://netloc value) or a trusted local absolute path (no scheme or netloc, just a /path value). It does this in part by checking if a netloc is provided on line 45 and again on line 49. If a netloc is provided then the string “url” is assumed to be a URL and a check is performed to verify that the URL aligns with the allowed origin, but if a netloc is not provided then the string “url” is assumed to be a trusted absolute path and no check is needed.

The problem with the vulnerable code is that the validation is not complete. Line 45 only checks for the presence of a netloc component. By skipping a check for the scheme component, the code opens the door for an adversary to take advantage of a browser oddity.

Remember how a triple slash URL is parsed by urlparse() to be an empty netloc and a longer path component. This empty netloc causes the conditionals on lines 45 and 49 to fail, and thus the allow origin check on lines line 50-56 is not called. After skipping the allow origin check, the code falls directly to line 61 and redirects the user to the supplied string `url` where the browser ignores the extra slash and redirects the application to `https://www.example.org/our-impact` (note only two slashes in where the browser redirects).

Jupyter_server must better recognize the format of the supplied URL as not matching the desired intention and not allowing the redirect by following the code on line 57.

**Exploit:**

To exploit this vulnerability an adversary must construct a GET or POST request that contains a crafted “next” parameter. This request would be directed to a web application that uses a vulnerable version of Jupyter Server. Such a request would be the GET URL crafted below:

    https://www.example.org/?next=https:///www.malicious_site.com

This URL — maybe sent via an email to a target user — would appear to come from a trusted application and the target user may be comfortable following the URL for that reason.

Looking closer at the example URL, the value of the “next” parameter would not be compared to the allow_origin due to the lack of a netloc component, and would be passed directly to the redirect() call. The underlying Tornado Web Framework would process the redirect() call and send a response back to the user’s client with a 301 or 302 status code signaling the web client to connect to the malicious URL.

**Mitigation:** To address this issue the neutralization code within the Jupyter code was improved. The first change was to add additional validation code before the call to urlparse().

The new code on line 52 searches for a colon in the user provided string “url” and explicitly adds the proper `://` separator between the scheme and the rest of the URL on line 53. This approach works since only http or https schemes are accepted and hence the `://` separator is required. Additional validation could have been added to verify that the value assigned to scheme exactly matches “http” or “https” which would further prevent adversaries from redirecting to unexpected components that communicate over custom schemes which can have more powerful capabilities that could be exploited.

    fixed file: jupyter_server/auth/login.py
    
    51		if ":" in url:
    52			scheme, _, rest = url.partition(":")
    53			url = f"{scheme}://{rest.lstrip('/')}"
    54		parsed = urlparse(url)
    …
    58		if (parsed.scheme or parsed.netloc) or not (parsed.path + "/").startswith(self.base_url):
    …
    62			if parsed.scheme or parsed.netloc:

The second change adds a check for scheme similar to the existing check for netloc. This change was made in two different locations on lines 58 and 62. These expanded checks more accurately enforce the condition where an absolute path is provided. Specifically, an absolute path doesn’t include a scheme or a netloc.

**Conclusion:** The changes made improve the neutralization efforts in the code and remove the root cause weakness “Improper Validation of Syntactic Correctness of Input”. Without this validation weakness, and with the previous protections still in place, the user controlled input that reaches the redirect() call no longer redirects the application beyond a trusted absolute path or a location within the allowed origin.

**References:**

Jupyter Server Project Page: https://jupyter-server.readthedocs.io/en/latest/

CVE-2023-39968 Entry: https://www.cve.org/CVERecord?id=CVE-2023-39968

CWE-601 Entry: https://cwe.mitre.org/data/definitions/601.html

CWE-1286 Entry: https://cwe.mitre.org/data/definitions/1286.html

OSV Vulnerability Report:
https://osv.dev/vulnerability/GHSA-r726-vmfq-j9j3

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2023-39968

Jupyter Server Code Commit to Fix Issue: https://github.com/jupyter-server/jupyter_server/commit/290362593b2ffb23c59f8114d76f77875de4b925

Red Hat Bugzilla Report: https://bugzilla.redhat.com/show_bug.cgi?id=2235743

tornado.web Web Framework Documentation: https://www.tornadoweb.org/en/stable/web.html

IETF RFC 1738 Uniform Resource Locators: https://www.ietf.org/rfc/rfc1738.txt

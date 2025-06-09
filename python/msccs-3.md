# MSCCS-3 :: OBSERVABLE TIMING DISCREPANCY IN PICCOLO

**Introduction:** An observable timing discrepancy during the execution of an application can reveal security-relevant information. Even small variations in timing can be exploited by adversaries to indirectly infer certain details about the product's internal operations or the data it operates on. In 2023 such a vulnerability was disclosed in the Python-based Piccolo application. This case study looks at that vulnerability, what it allowed an adversary to achieve, and how the code was eventually corrected.

**Language:** Python  
**Software:** Piccolo  
**URL:** https://github.com/piccolo-orm/piccolo

**Weakness:** CWE-208: Observable Timing Discrepancy

The weakness “Observable Timing Discrepancy” (also known as a type of “Information Exposure”) exists when an application performs different resource intensive operations depending on the internal state of the execution. If the difference in time to complete these operations is significant enough, then an adversary can measure the difference and gain knowledge about the internal state and the data being operated on.

**Vulnerability:** CVE-2023-41885 – Published 12 September 2023

The vulnerable code is part of the login() method defined on line 191 of the tables.py file.
vulnerable file: piccolo/apps/user/tables.py

    190	@classmethod
    191	async def login(cls, username: str, password: str) -> t.Optional[int]:
    …
    208		response = (
    209			await cls.select(cls._meta.primary_key, cls.password)
    210			.where(cls.username == username)
    211			.first()
    212			.run()
    213		)
    214		if not response:
    215			# No match found
    216			return None
    217
    218		stored_password = response["password"]
    219
    220		algorithm, iterations_, salt, hashed = cls.split_stored_password(
    221			stored_password
    222		)
    223		iterations = int(iterations_)
    224
    225		if cls.hash_password(password, salt, iterations) == stored_password:
    …
    235			return response["id"]
    236		else:
    237			return None

After some benign length checks of the provided username and password (not shown), lines 208-213 attempt to retrieve the stored password for the username that has been provided. If the username does not exist, then nothing is retrieved and line 216 will return “None”. If the username is found, then execution continues to line 225 that compares the related stored password (which is properly stored as a salted hash) against the hash of the provided password. If the provided password matches the stored password then the login() method returns the user id on line 235 signaling a valid login, otherwise it returns “None” on line 237.

Note that the code follows best practice and returns the exact same response (i.e., lines 216 and 237 are both “return None”) if the username is not found or if the password doesn’t match. This prevents a common attack where the adversary attempts to determine if a username is valid by comparing the response across a large number of login attempts using different usernames and looking for any differences in those responses, thus signaling which usernames are valid.

However, an observable timing discrepancy is present due to the time it can take to perform the hash_password() method. If a correct username is provided then the hash_password() method is called on line 225 which takes additional time to compute. If an incorrect username is provided then the hash_password() method is never called.

**Exploit:** CAPEC-462: Cross-Domain Search Timing

An adversary could use this vulnerability to determine the validity of a given username, or to create a list of users currently registered in the system. To do this, the adversary could construct a request with a potential username, send the request to the login() function, and then measure the time it takes for the software to respond. Performing this step multiple times, each with a different potential username, and recording the response time for each, will result in a dataset with two general response times. The short response time will be associated with valid usernames and the long response time will be associated with invalid usernames.

**Mitigation:** To address this issue the hash_password() method was added to the logic path where the provided username was not found in the system.

    fixed file: piccolo/apps/user/tables.py
    
    214		if not response:
    215			# No match found. We still call hash_password
    216			# here to mitigate the ability to enumerate
    217			# users via response timings
    218			cls.hash_password(password)
    219			return None

Even though there is no need to check the password in this logic path, calling the hash_password() method balances the related call made when the username is found, resulting in the function taking approximately the same amount of time to finish and return a response.

It is worth pointing out that to properly address the weakness, the code must resolve the potential issue where execution time between different numbers of iterations of hash_password() is measurable. The fixed code executes the following command when the username is found: `cls.hash_password(password, salt, iterations)`

It executes a slightly different command — without an iterations value — when the username is not found: `cls.hash_password(password)`

If providing an iteration value causes a measurably longer execution time as compared to the no iteration version of the call, then an adversary could still detect that difference and discover when a valid username was provided. However, looking at the implementation of hash_password(), line 156 shows that default value of `600,000` is used when no value is passed for iterations.

    fixed file: piccolo/apps/user/tables.py
    
    52		# The number of hash iterations recommended by OWASP:
    53		# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
    54		_pbkdf2_iteration_count = 600_000
    …
    135	@classmethod
    136	def hash_password(
    137		cls, password: str, salt: str = "", iterations: t.Optional[int] = None
    138	) -> str:
    …
    155		if iterations is None:
    156			iterations = cls._pbkdf2_iteration_count

Since an adversary will not know when a username’s password was hashed using the default number of iterations or a custom value, they will not be able to determine when hash_password() is being called during the invalid username situation or the valid usernames case.

**Conclusion:** The change to force expensive method calls to be made regardless of the logic path removes the possibility of timing discrepancies during execution of the software, thus removing the root cause weakness “Observable Timing Discrepancy”. Without this weakness adversaries are no longer able to determine valid usernames within the system.

**References:**

Piccolo Project Page: https://piccolo-orm.com/

CVE-2023-41885 Entry: https://www.cve.org/CVERecord?id=CVE-2023-41885

CWE-208 Entry: https://cwe.mitre.org/data/definitions/208.html

CAPEC-462 Entry: https://capec.mitre.org/data/definitions/462.html

OSV Vulnerability Report: https://osv.dev/vulnerability/PYSEC-2023-173

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2023-41885

Piccolo Code Commit to Fix Issue: https://github.com/piccolo-orm/piccolo/commit/edcfe3568382922ba3e3b65896e6e7272f972261

**Contributions:**

Originally created by Drew Buttner - The MITRE Corporation<br>
Reviewed by David Rothenberg - The MITRE Corporation<br>
Reviewed by Steve Christey - The MITRE Corporation

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a><br>

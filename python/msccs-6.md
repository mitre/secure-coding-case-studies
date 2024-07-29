# MSCCS-6 :: CODE INJECTION IN SEARCHOR

**Introduction:** The improper control over the generation of code (also known as “Code Injection”) has been a common mistake in software for many years. Annually one of the CWE™ Top 25 Most Dangerous Software Weaknesses, it is one that is theoretically possible in any coding language. In 2023 such a vulnerability was disclosed in Arjun Sharda's Searchor — an all-in-one Python library that simplifies web scraping, obtaining information on a topic, and generating search query URLs. This case study will explore that vulnerability, the mistake made by the developers, what it enabled an adversary to accomplish, and how the code was eventually corrected.

**Language:** Python  
**Software:** Searchor  
**URL:** https://github.com/ArjunSharda/Searchor

**Weakness:** CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code	

Code Injection — and more specifically dynamically evaluated code injection — is possible when software constructs all or part of a code segment using externally influenced input, but does not neutralize (e.g., canonicalize, encode, escape, quote, validate) or incorrectly neutralizes special elements known as directives that could modify the syntax and intended behavior of the code segment. This may allow an adversary to execute arbitrary code, or at least modify what code can be executed.

**Vulnerability:** CVE-2023-43364 – Published 25 September 2023

Searchor leverages the Python Click library to create an extensible, composable, and user-friendly command-line interface (CLI). The vulnerable source code in main.py defines the search command that can be used to query a specified URL.

    vulnerable file: src/searchor/main.py
    
    11	@cli.command()
    …
    28	@click.argument("engine")
    29	@click.argument("query")
    30	def search(engine, query, open, copy):
    31		try:
    32			url = eval(
    33				f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
    34			)
    35			click.echo(url)
    36			searchor.history.update(engine, query, url)
    37			if open:
    38				click.echo("opening browser...")
    39			if copy:
    40				click.echo("link copied to clipboard")
    41		except AttributeError:
    42			print("engine not recognized")

Line 30 defines the search() method and passes in four parameters: engine, query, open, copy. Of specific interest is the “engine” and “query” parameters that are provided by the user on line 28 and 29 respectively. No validation is performed on the values obtained.

The weakness is on line 33 where literal string interpolation (also known as f-strings) is used to construct a code segment based on the user provided parameters. Such interpolation is similar to basic string concatenation through Python methods like str.format().

The code segment is then passed into a call to eval() on line 32. An adversary that provides a specially crafted “engine” or “query” value could create additional code to be evaluated beyond the intended search() command. This is such a common type of code injection that it has been assigned its own weakness identifier (CWE-95) specific to dynamically evaluated code, typically through the use of a function like eval().

**Exploit:** CAPEC-242: Code Injection

An adversary could exploit this weakness by submitting a request to the search() method that contains a specially crafted malicious query. Consider the following parameter values:

    engine = ACME
    query = abc'),%20__import__('os').system('ls')%23
    open = False
    copy = False

The engine, open, and copy parameters are all normal expected values. The query parameter however is crafted to add an adversary chosen command to the end of the original command. Note that the `%20` is the URL encoding for the space character, and `%23` is the URL encoding for the “#” character. The resulting command created on line 33 from these values, and passed into the eval() function, would be:

`Engine.ACME.search('abc'), __import__('os').system('ls')#', copy_url=False, open_web=False)`

The single quotation mark in the first part of the adversary provided query parameter value `abc')` closes out the original search() command. This original command, which can be anything as it is expected to fail, becomes:

`Engine.ACME.search('abc')`

The comma in the adversary provided query parameter adds a second command to be processed by the eval() function:

'__import__('os').system('ls')'

This adversary inserted command performs a benign directory listing, but it could be modified to perform any desired command, including the use of the exec() command to execute any desired python expression. It would also be possible to create a command that opens a semi-permanent connection to the adversary’s system to enable remote control of the vulnerable system.
The trailing hash character “#” that is part of the adversary provided query parameter comments out the tail end of the original Engine command. Without this, the new command string would cause a syntax violation and not execute correctly.
Mitigation: To address this issue the use of the eval() function was removed and replaced on line 32 with a direct call to the Engine.search() method. Calling the search() method directly — instead of through an eval() command — completely removes the potential for Code Injection.

    fixed file: src/searchor/main.py
    
    32			url = Engine[engine].search(query, copy_url=copy, open_web=open)

An alternative, commonly-cited mitigation for this kind of weakness is to use the ast.literal_eval() function, since it is intentionally designed to avoid executing code. However, an adversary could still cause excessive memory or stack consumption via deeply nested structures, so the python documentation discourages use of ast.literal_eval() on untrusted data.

**Conclusion:** The change made to the code removes the weakness “Improper Neutralization of Directives in Dynamically Evaluated Code”. With the weakness resolved, the potential for Code Injection attacks is mitigated.

**References:**

Searchor Project Page: https://github.com/ArjunSharda/Searchor

CVE-2018-25088 Entry: https://www.cve.org/CVERecord?id=CVE-2023-3364

CWE-94 Entry: https://cwe.mitre.org/data/definitions/94.html

CAPEC-242 Entry: https://capec.mitre.org/data/definitions/242.html

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-66m2-493m-crh2

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2023-3364

Searchor Code Commit to Fix Issue: https://github.com/ArjunSharda/Searchor/commit/16016506f7bf92b0f21f51841d599126d6fcd15b

Click and Python: Build Extensible and Composable CLI Apps: https://realpython.com/python-click/

Searchor-2.4.0-POC-Exploit: https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-

POC exploit for Searchor <= 2.4.2: https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection

How ast.literal_eval can cause memory exhaustion: https://www.reddit.com/r/learnpython/comments/zmbhcf/how_astliteral_eval_can_cause_memory_exhaustion/

Python Documentation for ast.literal_eval(): https://docs.python.org/3/library/ast.html#ast.literal_eval


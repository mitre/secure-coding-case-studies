# MSCCS-4 :: PATH TRAVERSAL IN PYMDOWN-EXTENSIONS

**Introduction:** When applications do not control which parts of the file system can be accessed on behalf of other users, it can allow adversaries to read or write unexpected files, often leading to code execution, reading sensitive data, or causing a denial of service. The underlying source code weakness that makes such attacks possible is annually one of the CWE™ Top 25 Most Dangerous Software Weaknesses, ranking at number 8 in the 2023 list. In 2023, a vulnerability based on this weakness was disclosed in the pymdown-snippets extension of the pymdown-extensions pip package. This case study looks at that vulnerability, the root cause mistake, what it allowed an adversary to achieve, and how the code was eventually corrected.

**Language:** Python  
**Software:** pymdown-extensions  
**URL:** https://github.com/facelessuser/pymdown-extensions

**Weakness:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory

The weakness “Improper Limitation of a Pathname to a Restricted Directory” (also called “Path Traversal”) exists when an application accepts a user-controlled input, uses that input to construct a pathname that should be within a restricted directory, then reads or writes to the resulting filename without neutralizing navigation commands such as “..” in the user-controlled input. Unfortunately, this can allow an adversary to cause the application to access files in unauthorized locations elsewhere in the file system.

**Vulnerability:** CVE-2023-32309 – Published 15 May 2023

The pymdown-extensions package contains an extension called pymdown-snippets, which inserts the contents of “snippet” files into markdown documents. This makes it easier for users to manage and modularize documentation by inserting the same snippet into multiple markdown files, such as footers or contact information.

The extension works by preprocessing a markdown file, looking for special insert commands that specify which “snippet” files to insert into the markdown, and inserting the contents of the snippets in the output. The extension stores these snippets under a “base location” directory, which is defined by the administrator using a “base_path” setting. Unfortunately, the code does not properly neutralize special characters within the snippet pathname, which can cause the pathname to point to a location that is outside of the base location (i.e., access files that are not in the directory where snippets are stored).

The weakness in the code stems from the fact that the argument "lines" to the parse_snippets() function on line 210 is tainted (i.e., user controlled), and could contain special character sequences like `../` that would result in a snippet file path that is not restricted to the base_path.

The snippet file is then opened for reading on line 311, and the contents of the file are ultimately appended to the lines in the generated markdown file. An adversary that controls that original lines argument could use this path traversal weakness to open and read any file of their choosing.

    vulnerable file: pymdownx/snippets.py
    
    79		def __init__(self, config, md):
    80			"""Initialize."""
    81
    82			base = config.get('base_path')
    83			if isinstance(base, str):
    84				base = [base]
    85			self.base_path = base
    …
    155	def get_snippet_path(self, path):
    156		"""Get snippet path."""
    157
    158		snippet = None
    159		for base in self.base_path:
    160			if os.path.exists(base):
    161				if os.path.isdir(base):
    162					filename = os.path.join(base, path)
    163					if os.path.exists(filename):
    164						snippet = filename
    165						break
    …
    174		return snippet
    …
    210	def parse_snippets(self, lines, file_name=None, is_url=False):
    …
    220		for line in lines:
    221			# Check for snippets on line
    222			inline = False
    223			m = self.RE_ALL_SNIPPETS.match(line)
    …
    255			if m:
    …
    258				path = m.group('snippet')[1:-1].strip() if inline else m.group('snippet').strip()
    …
    301				snippet = self.get_snippet_path(path) if not url else path
    302
    303				if snippet:
    …
    309					if not url:
    310						# Read file content
    311						with codecs.open(snippet, 'r', encoding=self.encoding) as f:
    …
    352	def run(self, lines):
    353		"""Process snippets."""
    …
    359		return self.parse_snippets(lines)

Exploring this further, tainted data enters the code as part of the run() method on line 352 which is called with the lines of the markdown file as an argument. Since this markdown file could be modified by untrusted users, all lines within it are considered tainted. The run() method then passes the tainted lines to the parse_snippets() method which is defined on line 210.

On line 223, the code performs a regular-expression search of each tainted line, looking for the special commands that specify a snippet filename. If a match is found, then it extracts the path specified in the markdown on line 258 and passes the tainted path on line 301 to get_snippet_path().

The method get_snippet_path() is defined on line 155 and uses the os.path.join() method on line 162 to build a file path to the snippet using the tainted path argument that was passed in. The resulting snippet path is returned on line 174 and used on line 311 as previously described to open the file and read its contents.

**Exploit:** CAPEC-126: Path Traversal

To exploit this weakness, an adversary must construct or modify a markdown file containing a malicious insert command that points to unexpected locations, then upload the file to a server that is using a vulnerable pymdown-snippets version.
Suppose the base location directory is /server/pymdown-ext/snippets/. Within a markdown file, the code looks for insert commands such as: `--8<-- "contact-us.md"`

The `--8<--` prefix is used to represent the snippet insert command, and `contact-us.md` is the snippet file to insert.

In get_snippet_path(), the os.path.join() call would combine the base location and the snippet filename to produce a snippet file path such as: `/server/pymdown-ext/snippets/contact-us.md`

However, an adversary could change or add a markdown file to contain a malicious snippet command such as: `--8<-- "../../../../etc/passwd"`

The os.path.join() call would produce this snippet file path name:
/server/pymdown-ext/snippets/../../../etc/passwd

When passed to the file read call on line 311 of the vulnerable source code, the operating system would resolve the "../" sequences, moving through parent directories, to produce: `/etc/passwd`

In this example, the adversary would have caused the contents of the password file to be inserted into the returned markdown document!

**Mitigation:** The issue was fixed with two primary changes to the source code:
1)	Define a "restrict_base_path" option to allow the snippet admin to specify the directory under which all files must be stored.
2)	Use absolute paths to ensure that the generated filename is under the expected base path (as quoted in the patch: “restrict snippets to be actual children of the base path”).

The first change was to the \_\_init\_\_() method which sets a new “restrict_base_path” variable on line 86 directly from a new corresponding setting in the configuration on line 375. Additionally, line 85 was added to create a normalized absolutized version of the base_path obtained from the configuration. This normalization collapses redundant separators and up-level references within the provided base_path value. (e.g., A/foo/../B becomes A/B)

    fixed file: pymdownx/snippets.py
    
    79 def __init__(self, config, md):
    80     """Initialize."""
    81
    82     base = config.get('base_path')
    83     if isinstance(base, str):
    84         base = [base]
    85     self.base_path = [os.path.abspath(b) for b in base]
    86     self.restrict_base_path = config['restrict_base_path']
    …
    373    self.config = {
    374        'base_path': [["."], "Base path for snippet paths - Default: [\".\"]"],
    375        'restrict_base_path': [
    376            True,
    377            "Restrict snippet paths such that they are under the base paths - Default: True"
    378        ],

The second change was to the get_snippet_path() method where the original os.path.join() call was removed and replaced by lines 163-169. This added code obtains the normalized file path for the snippet file on line 164, then on line 166 ensures that the snippet file is in the same directory as the base_path.

    fixed file: pymdownx/snippets.py
    
    156	def get_snippet_path(self, path):
    157		"""Get snippet path."""
    158
    159		snippet = None
    160		for base in self.base_path:
    161			if os.path.exists(base):
    162				if os.path.isdir(base):
    163					if self.restrict_base_path:
    164						filename = os.path.abspath(os.path.join(base, path))
    165						# If the absolute path is no longer under the specified base path, reject the file
    166 						if not os.path.samefile(base, os.path.dirname(filename)):
    167							continue
    168					else:
    169						filename = os.path.join(base, path)

**Conclusion:** The changes made to the pymdown-extensions source code prevent malicious sequences such as “../” or even “/” from causing the extension to generate unexpected pathnames. With the weakness resolved, user-controlled input that reaches the get_snippet_path() method will only produce pathnames under the base path or trigger an error, thus preventing the access of files outside the restricted base path and the potential exposure of sensitive information.

**References:**

PyMdown Extensions Project Page: https://github.com/facelessuser/pymdown-extensions/

CVE-2023-32309 Entry: https://www.cve.org/CVERecord?id=CVE-2023-32309

CWE-22 Entry: https://cwe.mitre.org/data/definitions/22.html

CAPEC-66 Entry: https://capec.mitre.org/data/definitions/126.html

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-jh85-wwv9-24hv

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2023-32309

PyMdown Extensions Code Commit to Fix Issue: https://github.com/facelessuser/pymdown-extensions/commit/b7bb4878d6017c03c8dc97c42d8d3bb6ee81db9d

**Contributions:**

Originally created by Steve Christey - The MITRE Corporation<br>
Reviewed by Drew Buttner - The MITRE Corporation<br>
Reviewed by David Rothenberg - The MITRE Corporation

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a><br>

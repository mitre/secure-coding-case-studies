
# PATH TRAVERSAL IN AGENT-ZERO

## Introduction

One of the more frustrating vulnerability classes in web development is path traversal — not because it is complicated, but because it is so avoidable. When a server accepts a filename or file path from a user and then opens that path without checking where it actually points, an attacker can inject traversal sequences like `../` to walk up the directory tree and read files the application was never meant to serve. [CWE-22](https://cwe.mitre.org/data/definitions/22.html), which covers this weakness, consistently appears on the CWE Top 25 Most Dangerous Software Weaknesses list, a sign that developers keep making this mistake across languages and frameworks despite it being well understood.

Agent Zero is an open-source AI agent framework built in Python. It gives users a web interface to run autonomous AI agents that can execute shell commands, read and write files, browse the web, and interact with external APIs — essentially, a general-purpose AI assistant that operates directly on the host machine or inside a Docker container. In early 2026, a path traversal vulnerability was found in Agent Zero's file download endpoint. Any authenticated user could craft a single HTTP request and read any file on the server that the application process had permission to open. This case study walks through how the vulnerable code was structured, how an attacker could exploit it, what the patch looked like, and — most importantly — how this type of mistake can be systematically avoided.

## Software

**Name:** Agent Zero  
**Language:** Python  
**URL:** <https://github.com/frdel/agent-zero>

## Weakness

[CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

Path traversal vulnerabilities share a common shape: the application intends to confine file access to some root or working directory, but it constructs the final file path from user input without confirming that the result actually stays inside that root. The attacker's job is to provide input that steers the path outside the boundary.

In Python specifically, there is a tricky behavior in the standard library function `os.path.join()` that catches many developers off guard. The function is designed to build file paths by joining a series of components together. Most people expect that if you pass a base directory as the first argument, the result will always be somewhere under that base. That assumption is wrong. Python's documentation is clear about this, but it is easy to miss: if any component passed to `os.path.join()` is itself an absolute path — one that starts with `/` on Linux/macOS or a drive letter on Windows — all the components before it are discarded. The following example illustrates the problem:

```python
import os
base_dir = "/workspace"
user_input = "/etc/passwd"
result = os.path.join(base_dir, user_input)
# result is '/etc/passwd' — base_dir is gone entirely
```

The developer wrote code that looks like it limits access to `/workspace`, but it does not. The moment a user supplies an absolute path, the base directory becomes meaningless. This behavior is the root cause behind CVE-2026-4307.

## Vulnerability

[CVE-2026-4307](https://www.cve.org/CVERecord?id=CVE-2026-4307) — Published 17 March 2026

Agent Zero includes an API endpoint called `/download_work_dir_file` that is meant to let users download files from their agent's working directory. The endpoint reads a `path` parameter from the query string and eventually calls a helper function, `get_abs_path()`, to turn it into an absolute filesystem path. That helper lives in `python/helpers/files.py` at lines 406–408:

```diff
vulnerable file: python/helpers/files.py

 406 def get_abs_path(*relative_paths):
 407     """Convert relative paths to absolute paths based on the base directory."""
 408     return os.path.join(get_base_dir(), *relative_paths)
```

That is the entire function. It calls `get_base_dir()` to get the application's root directory, then passes it and the user's input straight into `os.path.join()`. There is no check that the result is still inside the base directory. There is no call to `Path.resolve()` to canonicalize the path. The function simply trusts that `os.path.join()` will handle things correctly — but as shown above, it will not when the user supplies an absolute path.

To see how a request flows through this code, the vulnerable source in `python/api/download_work_dir_file.py` at lines 84–92:

```diff
vulnerable file: python/api/download_work_dir_file.py

  84 async def download_work_dir_file(request):
  85     path = request.rel_url.query.get("path", "")
  86     ...
  87     info = await file_info.get_file_info(path)
  88     ...
  92     return web.FileResponse(info["abs_path"])
```

And in `python/api/file_info.py`, line 29, the path is handed off with no validation:

```diff
vulnerable file: python/api/file_info.py

  29 abs_path = files.get_abs_path(path)
```

The path from the query string is handed to `get_file_info()`, which hands it to `get_abs_path()`, which hands it to `os.path.join()`. At no point does any of this code ask whether the resulting path is still inside the working directory. If a user sends `GET /download_work_dir_file?path=/etc/passwd`, the server resolves the path to `/etc/passwd` and streams its contents back. The intended restriction to the working directory is bypassed completely.

What makes this more striking is that the same codebase already had a correct implementation of path validation sitting in a different file. The `FileBrowser` class in `python/helpers/file_browser.py` does this properly:

```diff
protected file: python/helpers/file_browser.py

 full_path = (self.base_dir / file_path).resolve()
 if not str(full_path).startswith(str(self.base_dir)):
     raise ValueError("Invalid path")
```

This code resolves the path first — collapsing any `..` sequences — and then checks that the result still starts with the base directory. That is exactly what `get_abs_path()` should have done. The vulnerability did not exist because the team did not know how to write the check; it existed because the check was written in one place and not applied in another.

## Exploit

[CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)

Exploiting this vulnerability requires an authenticated session with Agent Zero's web interface. However, that bar is lower than it sounds: by default, Agent Zero does not require a password unless the user explicitly sets one during setup. Many self-hosted deployments running locally or on a private network may have no authentication configured at all.

An attacker starts by grabbing a CSRF token, which Agent Zero requires for API requests:

```
RESPONSE=$(curl -s -c /tmp/cookies.txt "http://target:50001/csrf_token")
TOKEN=$(echo $RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)
```

With the token, reading any file the process can access takes one more request:

```
curl -s -b /tmp/cookies.txt \
     -H "X-CSRF-Token: $TOKEN" \
     "http://target:50001/download_work_dir_file?path=/etc/passwd"
```

The server returns the full file contents. From there, an attacker would target whatever is most sensitive on that particular host. Common high-value files in an Agent Zero deployment include:

| Target File | What Gets Exposed |
|---|---|
| `/etc/passwd` | System user accounts |
| `/etc/shadow` | Password hashes (if the process runs as root) |
| `/a0/.env` | API keys, `ROOT_PASSWORD`, `A0_PERSISTENT_RUNTIME_ID` |
| `/proc/self/environ` | Live environment variables for the running process |
| `~/.ssh/id_rsa` | SSH private keys |
| Cloud credential files | AWS, GCP, or Azure access tokens |

The `.env` file deserves special attention. It contains the `A0_PERSISTENT_RUNTIME_ID`, which is used to derive authentication tokens in some configurations. Obtaining this value can open the door to MCP endpoint access and, from there, remote code execution. None of this appears unusual in standard application logs, so the attack is quiet — by the time anyone notices something is wrong, data may already be gone.

Fix

Agent Zero addressed CVE-2026-4307 in release v1.9. The patch was applied in `python/api/download_work_dir_file.py`: before the endpoint opens any file, it now resolves the requested path to its canonical form and verifies that the result falls within the application's runtime base directory. Any request whose resolved path lands outside that directory is rejected before a single byte of file content is read.

The core fix was applied to `get_abs_path()` in `python/helpers/files.py`, bringing it in line with the validation that `FileBrowser` had always used correctly:

```diff
fixed file: python/helpers/files.py

 406 def get_abs_path(*relative_paths):
-407     """Convert relative paths to absolute paths based on the base directory."""
-408     return os.path.join(get_base_dir(), *relative_paths)
+407     """Safely convert relative paths to absolute paths, confined to base dir."""
+408     from pathlib import Path
+409     base_dir = Path(get_base_dir()).resolve()
+410     joined = os.path.join(str(base_dir), *relative_paths)
+411     resolved = Path(joined).resolve()
+412     try:
+413         resolved.relative_to(base_dir)
+414     except ValueError:
+415         raise ValueError(f"Path escapes base directory: {resolved}")
+416     return str(resolved)
```

Two things changed. First, `Path.resolve()` is called on the final path before anything else happens. This flattens out `..` segments, follows symlinks, and removes any ambiguity about where the path actually points. Second, `relative_to(base_dir)` checks that the resolved path is a descendant of the base directory — if it is not, Python raises a `ValueError` and the request is dead before the filesystem is touched. The fix is small but the effect is complete: the `os.path.join()` absolute-path bypass no longer works because the check happens after the path is fully resolved, not before.

Prevention

Path traversal vulnerabilities are preventable. The challenge is not that the fix is hard to write — as the diff above shows, it is a handful of lines. The challenge is making sure it gets applied everywhere it needs to be, not just in the one place someone happened to think of it.

**Resolve first, check second.** The correct pattern for any code that constructs a file path from user input is: join the components, call `Path.resolve()` to canonicalize, then verify the result is still inside the intended base directory. Trying to validate the raw input string by searching for `..` or `/` before constructing the path does not work reliably. Encodings, double-encoding, and URL normalization can all reintroduce traversal sequences after an early string check has already passed. The only path worth validating is the fully resolved one, because that is what the OS will actually open.

**Treat `os.path.join()` with user input as a red flag.** The absolute-path discarding behavior in Python's `os.path.join()` is documented, but it is not intuitive, and it catches experienced developers as well as beginners. A practical rule: if any argument to `os.path.join()` could come from outside the application, the result must go through `Path.resolve()` and `relative_to()` before being used. Using the `/` operator from Python's `pathlib` module instead — `Path(base_dir) / user_input` — combined with a resolve-and-check step is even cleaner. Tools like [Bandit](https://bandit.readthedocs.io/en/latest/), a static analyzer for Python security issues, can flag calls to `os.path.join()` where one argument comes from tainted input, making these cases easier to catch in code review or CI pipelines.

**Standardize path validation into one shared function and use it everywhere.** What went wrong in Agent Zero is not that a secure implementation did not exist — `FileBrowser` had one. What went wrong is that the download endpoint used a different, unvalidated helper instead. This is a consistency problem, and consistency problems are best solved structurally. A single canonical safe function for resolving file paths, with every file-serving endpoint required to use it, makes the problem hard to introduce by accident. A mix of validated and unvalidated path helpers in the same codebase is a risk waiting to surface in exactly the way it did here.

**Minimize what an escaped path can actually reach.** Running Agent Zero in Docker — which the project recommends — is genuinely good defense-in-depth. Inside a container with a minimal filesystem, a successful traversal can only reach files that were mounted into it. Separating secrets into a runtime secrets manager rather than a plaintext `.env` file accessible to the application process further limits the damage. In this incident, the `.env` file being readable by the process meant that a successful path traversal could expose API keys and credentials directly. Running as a non-root user inside the container also means that even if `/etc/shadow` is reached, the process will not have permission to read it.

**Add negative tests for every file-serving endpoint.** Most test suites check that valid inputs produce the correct output. Security-relevant endpoints also need to verify that invalid inputs produce the correct errors. For any API that accepts a file path, the test suite should include cases that pass in `../` sequences, absolute paths starting with `/`, and null bytes embedded in the middle of a path — and assert that each returns an error rather than file contents. Automated fuzzing with a list of known path traversal payloads can catch regressions as the codebase grows, and it would have caught this vulnerability before any code was released.

Critical Analysis

What makes CVE-2026-4307 particularly worth studying is not the technical complexity of the bug — the actual mistake is just a few missing lines of validation. What is worth paying attention to is the engineering failure that allowed it to exist in the first place, especially given that a correct implementation was already sitting in the same repository.

The `FileBrowser` class had secure path validation. The `get_abs_path()` helper did not. Both were available to the download endpoint's author, and the wrong one was used. That is not a knowledge gap — it is a design consistency problem. When a codebase has multiple utilities that all appear to do the same job (resolve a file path), but only some of them are actually safe to use with untrusted input, the odds increase that someone will reach for the wrong one. The more spread out security-critical logic is across a project, the harder it becomes to reason about whether any given endpoint is actually protected.

This points to a broader principle in secure software design: security-critical operations like path validation should not be duplicated across components. They should be encapsulated in a single, well-tested function that the rest of the application is required to go through — not one of several options a developer can choose from. If `get_abs_path()` had been the one and only way to resolve a file path in Agent Zero, and if it had included the boundary check from the start, the download endpoint would have been protected automatically. The vulnerability only became possible because there was an escape hatch — an alternative helper that skipped the check — and someone unknowingly used it.

The code review and testing gaps compound this. A single negative test case — sending `/etc/passwd` as the `path` parameter and asserting the response is an error — would have caught this before it ever reached users. That test was never written. Automated static analysis with a tool like Bandit would have flagged the `os.path.join()` call with external input as worth reviewing. That was not run either, or at least not acted on. Neither of these is an exotic or expensive technique; they are standard parts of a security-conscious development process that were simply absent here.

Ultimately, CVE-2026-4307 is less about a subtle Python quirk in `os.path.join()` and more about what happens when secure coding is treated as something individual developers are responsible for remembering, rather than something the system enforces. The quirk was the mechanism. The real cause was the lack of centralized controls, inconsistent application of existing secure patterns, and a test suite that only asked whether things worked correctly — never whether they failed safely.

## Conclusion

CVE-2026-4307 is a good example of a vulnerability that was not the result of ignorance or cutting corners — the project already had correct path validation code, written by the same team, in the same repository. The problem was that the download endpoint used a different helper that skipped the validation step, and nobody caught the inconsistency before it shipped. One HTTP request with an absolute path in the query string was enough to read any file on the server. The patch was a few lines of code. The real takeaway is that secure coding practices only hold if they are applied uniformly: having one safe path function sitting next to one unsafe one does not make the application safe. Consistency in applying validation — backed by static analysis and targeted negative testing — is what actually keeps these vulnerabilities out of production.

References

Agent Zero Project Page: <https://github.com/frdel/agent-zero>

CVE-2026-4307 Entry: <https://www.cve.org/CVERecord?id=CVE-2026-4307>

CWE-22 Entry: <https://cwe.mitre.org/data/definitions/22.html>

CAPEC-126 Entry: <https://capec.mitre.org/data/definitions/126.html>

NVD Vulnerability Report: <https://nvd.nist.gov/vuln/detail/CVE-2026-4307>

VulDB Vulnerability Report: <https://vuldb.com/?id.351337>

Public Exploit (PoC): <https://gist.github.com/YLChen-007/1819c843ad26aaaaecdc768a789df022>

Agent Zero v1.9 Release Notes (Fix): <https://github.com/frdel/agent-zero/releases/tag/v1.9>

Bandit Python Static Analyzer: <https://bandit.readthedocs.io/en/latest/>

Python os.path.join Documentation: <https://docs.python.org/3/library/os.path.html#os.path.join>

Contributions

Originally created by Sahithi Thulluri – George Mason University  
Originally created by Nithin Akula – George Mason University

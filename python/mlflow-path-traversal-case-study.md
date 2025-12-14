# Path Traversal In MLflow Model Registry

## Introduction

Many software systems read and write files based on user input. If the software does not safely check or clean these file paths, an attacker can trick it into reading files that should never be exposed. This type of mistake is called a **path traversal** weakness and is tracked as **CWE-22**, one of the most common and dangerous issues in real software.

In 2024, a path traversal vulnerability (**CVE-2024-1558**) was found in the MLflow Model Registry. MLflow is a popular machine learning lifecycle tool used by many companies. The issue came from the way MLflow validated the `source` field when creating a model version. The code only checked part of the path and later used the full value. This may cause an attacker to read sensitive files from the MLflow server.

This case study explains the weakness, walks through the vulnerable code, shows how an attacker could abuse it, and describes how the MLflow team fixed it in version **2.12.1**.

---

## Software

**Name**  
MLflow (Model Registry / Tracking Server)

**Language**  
Python

**URL**  
https://github.com/mlflow/mlflow

---

## Weakness

**CWE-22: Path Traversal**

This weakness occurs when software uses a file path that comes from outside input but does not check it properly. Attackers can include special values like `..`, `/`, or encoded versions (`%2e%2e%2f`) to escape from a safe directory and reach files elsewhere on the system.

A simple example in Python:

```
def read_file(name):
    base = "/var/app/files"
    full_path = base + "/" + name   # BAD: no validation
    return open(full_path).read()
```

If a user sends:

```
../../etc/passwd
```

the OS may turn this into:

```
/etc/passwd
```

giving access to sensitive data.

Common causes include:

- Checking only part of a URI
- Failing to normalize or clean the path
- Treating paths as strings instead of using structured tools (`pathlib`, `urlparse`)
- Using the unvalidated value later in the code

The MLflow issue is a direct example of these mistakes.

---

## Vulnerability

**CVE-2024-1558: Path Traversal in MLflow Model Registry**

MLflow lets users create a model version by providing a `source` field that points to the model's artifact location. Later, MLflow uses this `source` value to locate files on disk when a client asks for artifacts.

### What Went Wrong

MLflow attempted to validate `source` using a helper function. However:

- It checked **only the path part** of the URI.
- It ignored query strings, fragments, or encoded tricks.
- The validation did not normalize or decode the path.
- After validation, MLflow **still used the original, unsafe string**.

### Vulnerable Code 

```
vulnerable file: mlflow/server/handlers.py

# Validation only checks the parsed path, not the entire URI.
def _validate_non_local_source_contains_relative_paths(source):
    parsed = urllib.parse.urlparse(source)
    path = parsed.path
    if ".." in pathlib.PurePosixPath(path).parts:
        raise MlflowException("Relative paths not allowed")

# Later: uses the raw source string anyway.
def _create_model_version():
    req = _get_request_message(CreateModelVersion())
    _validate_non_local_source_contains_relative_paths(req.source)

    model_version = registry.create_model_version(
        name=req.name,
        source=req.source,   # ← raw, unsafe value used here
        run_id=req.run_id,
    )
```

### Why This Is Vulnerable

The validator only checks:

```
parsed.path
```

but ignores parts like:

```
file:///safe/path?x=../../../../etc/passwd
```

Since the `path` (`/safe/path`) looks harmless, validation passes. Later code still uses the full original value, including the dangerous query string. When MLflow later joins this `source` with a user-supplied artifact path, the filesystem operations may escape into arbitrary locations.

This vulnerability affected MLflow versions **before 2.12.1**.

---

## Exploit

**CAPEC-126: Path Traversal**

An attacker can exploit this by storing a model with a crafted `source` value, then requesting an artifact based on that stored value.

### Step 1 — Create a Fake Model Version

The attacker sends:

```
POST /api/2.0/mlflow/model-versions/create
{
  "name": "badmodel",
  "source": "file:///mlruns/0/abc/artifacts/model?x=../../../../etc/passwd",
  "run_id": "abc"
}
```

The validator looks only at:

```
/mlruns/0/abc/artifacts/model
```

and accepts it.

### Step 2 — Request an Artifact

```
GET /api/2.0/mlflow/model-versions/get-artifact?name=badmodel&version=1&path=whatever
```

Internally, MLflow joins the unsafe stored source with the provided artifact path. Because the original unsafe URI remains unchanged, MLflow may open `/etc/passwd` or any file readable by the server.

---

## Fix

MLflow fixed the issue in **version 2.12.1**.

The fix includes two important parts:

1. Stronger validation and normalization  
2. Using only the validated value everywhere

### Fixed Code 

```
fixed file: mlflow/server/handlers.py

def _validate_and_normalize_source(source):
    parsed = urllib.parse.urlparse(source)

    if parsed.scheme not in ["file", "s3", "gs"]:
        raise MlflowException("Unsupported scheme")

    normalized = pathlib.PurePosixPath(urllib.parse.unquote(parsed.path))
    if ".." in normalized.parts:
        raise MlflowException("Relative paths not allowed")

    safe_parsed = parsed._replace(path=str(normalized))
    return safe_parsed.geturl()

def _create_model_version():
    req = _get_request_message(CreateModelVersion())
    safe_source = _validate_and_normalize_source(req.source)

    model_version = registry.create_model_version(
        name=req.name,
        source=safe_source,
        run_id=req.run_id,
    )
```

---

## Prevention

### 1. Treat Paths and URIs as Structured Data  
Use `urlparse`, `pathlib`, and normalized paths instead of raw strings.

### 2. Enforce a Base Directory  
Always ensure that resolved paths remain inside an allowed root.

### 3. Validate Once, Use the Validated Value  
Never validate a value then use the unvalidated version later.

### 4. Allowlist Allowed Schemes  
Block unexpected schemes entirely.

### 5. Normalize and Decode Paths  
Prevent traversal attempts before doing any file access.

### 6. Add Tests for Path Traversal  
Test encoded and unencoded traversal cases.

### 7. Use Code Review and Static Analysis  
Check for unsafe path handling during reviews.

---

## Conclusion

CVE-2024-1558 shows how partial validation of a file path can lead to serious security issues. MLflow validated only part of the URI and then used the original value to read files. An attacker could use this to read sensitive files from the server. MLflow fixed the issue by normalizing paths, checking schemes, and using only the validated value. These practices help reduce the chance of similar bugs in other systems.

---

## References

- MLflow Project Page: https://github.com/mlflow/mlflow
- CVE-2024-1558 Entry (NVD): https://nvd.nist.gov/vuln/detail/CVE-2024-1558
- GitHub Advisory (GHSA-j62r-wxqq-f3gf): https://github.com/advisories/GHSA-j62r-wxqq-f3gf
- OSV Report: https://osv.dev/vulnerability/GHSA-j62r-wxqq-f3gf
- CWE-22 Entry: https://cwe.mitre.org/data/definitions/22.html
- CAPEC-126 Entry: https://capec.mitre.org/data/definitions/126.html
- Huntr Report: https://huntr.com/bounties/7f4dbcc5-b6b3-43dd-b310-e2d0556a8081
- MLflow 2.12.1 Release Announcement (mentions PR #11376):  
  https://groups.google.com/g/mlflow-users/c/-dCOO9wj2Tw
- Related Pull Request: MLflow PR #11376  
  https://github.com/mlflow/mlflow/pull/11376


---

## Contributions

Created by **Kanishk Vardan Gokula Krishnan – George Mason University**  
## License
This work is licensed under the Creative Commons Attribution 4.0 International License.
https://creativecommons.org/licenses/by/4.0/


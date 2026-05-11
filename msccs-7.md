# Title : Path Traversal (Zip Slip) in Plexus Archiver

## Introduction : 
ZIP files are commonly used to share software and groups of files. But if a program does not check the file paths inside a ZIP before extracting them, an attacker can put dangerous paths like ../ inside the archive. This can make the program write files outside the folder it is supposed to use. This type of issue is called Path Traversal, and it is on the CWE Top 25 list because it can lead to overwriting important files or even running malicious code.

A real example of this problem happened in Plexus Archiver, a Java library that many tools use to extract ZIP files. Versions before 3.6.0 had a mistake where the library trusted the file name inside the ZIP without checking if it was safe. This case study explains how this happened, shows the vulnerable code, how an attacker could use it, and how the developers fixed the problem.

## Software :
**Name:**Plexus Archiver
**Language:** Java 
**URL:** https://github.com/codehaus-plexus/plexus-archiver

## Weakness :
**CWE-22: Improper Limitation of a Pathname to a Restricted Directory (“Path Traversal”)**

This weakness happens when a program uses a file path that comes from outside input but does not check if the path is safe. An attacker can give a path like ../ which tells the system to move to a parent folder. If the program does not block this, the attacker can make the software read or write files outside the intended directory.

A common example is when a program extracts files from a ZIP archive and directly trusts the file name inside the ZIP. An attacker could put something like:

```
../../../../etc/passwd
```
inside the archive. If the program uses this name without checking, it may write the file outside the safe folder.

Here is a simple example showing the mistake:
```
String path = baseDir + "/" + userInputName;
FileOutputStream out = new FileOutputStream(path);
```
If userInputName contains dangerous path parts like ../, the program may write to places it should never touch.

## Vulnerability : 
**CVE-2018-1002200**
This vulnerability was found in Plexus Archiver, a Java library used by many tools to extract ZIP files. Versions before 3.6.0 did not properly check the file names stored inside the ZIP archive.
The issue happened because the library did not properly check the file paths stored inside ZIP entries. ZIP files can contain normal filenames like: 
docs/readme.txt
but they can also contain dangerous paths like: ../../../../etc/passwd

If a program extracts this ZIP using Plexus Archiver 3.5 or earlier, the library will use the file name exactly as it appears inside the ZIP. Because the library did not validate the file path, the extracted file may end up outside the target directory, which is a Path Traversal attack. 
In the vulnerable version (3.5), the library calls extractFileIfIncluded() and passes the ZIP entry name directly from the archive without any checks. Below is the part of the code where the unsafe behavior occurs.

Vulnerable Source Code : 
The vulnerable code shown in this section comes from Plexus Archiver version 3.5, available here: **https://github.com/codehaus-plexus/plexus-archiver/releases/tag/plexus-archiver-3.5**

**vulnerable file: src/main/java/org/codehaus/plexus/archiver/zip/AbstractZipUnArchiver.java (from Plexus Archiver 3.5)**

```
 170    while (e.hasMoreElements()) {
 171         ZipArchiveEntry ze = (ZipArchiveEntry) e.nextElement();
 172          ZipEntryFileInfo fileInfo = new ZipEntryFileInfo(zf, ze);
 173 
 174        if (isSelected(fileInfo.getName(), fileInfo)) {
 175            in = zf.getInputStream(ze);
 176
 177           
 178            extractFileIfIncluded(
 179                getSourceFile(),
 180                getDestDirectory(),
 181                in,
 182                fileInfo.getName(),     // <-- attacker-controlled path
 183                new Date(ze.getTime()),
 184                ze.isDirectory(),
 185                ze.getUnixMode() != 0 ? ze.getUnixMode() : null,
 186                resolveSymlink(zf, ze)
 187            );
 188
 189            in.close();
 190            in = null;
 191        }
 192    }
```
Explanation of the Mistake 
- fileInfo.getName() reads the file name from the ZIP file. 
- This value can include unsafe paths like ../ or /etc/passwd. 
- The code does not check if the name tries to escape the destination directory. 
- The code then passes the attacker-controlled name into extractFileIfIncluded(), which writes the file to disk. 

Because there is no validation, a malicious ZIP file can make Plexus Archiver write files anywhere on the system, not just inside the intended folder. This is the root cause of the Zip Slip vulnerability.


## Exploit :
**CAPEC-126: Path Traversal**

To exploit this vulnerability, an attacker creates a ZIP file that contains a file name with a path like ../ in it. ZIP tools allow any string as a file name, so the attacker can include something like:
../../../../etc/hosts

If a program uses Plexus Archiver 3.5 (or any version before 3.6.0) to extract this ZIP, the library will take the entry name directly and pass it to the extraction code without checking if the path is safe. This means the file will be written outside the target directory.

An example malicious ZIP entry might look like:
File name: ../../../../var/www/html/index.php
Content: attacker-controlled PHP code

When the program extracts this ZIP: 
1. Plexus Archiver reads the file name from inside the ZIP. 
2. It does not remove ../ or check if the path escapes the extraction folder. 
3. It writes the file exactly to the path given.

This can lead to: 
- overwriting system files 
- overwriting website files 
- planting backdoor scripts 
- modifying configuration files

Any application that relies on Plexus Archiver to safely extract ZIP files automatically becomes vulnerable if it processes a ZIP file from an untrusted source.

Because the library directly combines this filename with the output directory—without checking whether the path is safe—the file is extracted outside the intended folder. This allows an attacker to overwrite important system files, plant executable files in server directories, or modify configuration files.
If the ZIP extraction occurs automatically (for example, during file upload or plugin installation), the attacker can trigger the exploit simply by providing the crafted ZIP. The program unknowingly performs the write operation, leading to consequences such as system damage, corrupted data, or even remote code execution depending on where the malicious file is placed.

## Fix  : 
The Zip Slip vulnerability in Plexus Archiver was fixed in version 3.6.0 by adding a security check to ensure that extracted files cannot escape the destination directory. The fix was added inside the method extractFile() in the file:
**src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java**
**(https://github.com/codehaus-plexus/plexus-archiver/releases/tag/plexus-archiver-3.6.0)**

In earlier versions (such as 3.5), the code created the destination file using the ZIP entry name without validating the final resolved path. In version 3.6.0, the developers introduced a canonical path check before writing the file. This prevents entries containing ../ from being extracted outside the target folder.
Below is the relevant portion of the fixed code from the 3.6.0 release:

**Fixed Source Code :**
fixed file: src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java

```
  // Resolve the target file based on the entry name
  final File f = FileUtils.resolveFile(dir, entryName);

+ // Verify that the extracted file stays within the destination directory
+ String canonicalDirPath = dir.getCanonicalPath();
+ String canonicalDestPath = f.getCanonicalPath();
+
+ if (!canonicalDestPath.startsWith(canonicalDirPath)) {
+     throw new ArchiverException(
+         "Entry is outside of the target directory (" + entryName + ")"
+     );
+ }

```
Explanation of the Fix:

1. Canonical paths are computed 
 The method obtains the canonical (absolute, cleaned) paths of both the destination directory and the file being extracted. Canonical paths remove symbolic links and normalize directory traversal sequences like ../. 
2. The paths are compared 
The code checks whether the extracted file's canonical path begins with the extraction directory's canonical path. 
3. Malicious paths are blocked 
If the entry attempts to escape the directory—for example, with ../../etc/passwd—the path comparison fails. The library immediately throws an exception instead of writing the file. 

This change ensures that Plexus Archiver can no longer be tricked into writing files outside the intended extraction directory, fully mitigating the Zip Slip vulnerability.

## Prevention :

Preventing path traversal issues during file extraction requires validating all file paths before writing them to disk. The  lesson from this case study is that software must never trust the file names inside an archive. These names are controlled by whoever created the ZIP file, including attackers. The most reliable defense is to resolve each file path to its canonical form and ensure that it remains inside the intended extraction directory. 
This validation step must always happen before creating or writing any output file. One effective practice is to always compare the canonical path of the destination directory with the canonical path of the file that is about to be written. If the file path does not start with the directory path, the software should reject the entry. This is exactly the change applied in the fixed version of Plexus Archiver. If this type of check had been implemented earlier, the Zip Slip vulnerability would never have occurred. 
It is also important to avoid building file paths by simply concatenating strings (for example, new File(dir, entryName) without validation). File names should be normalized and checked for dangerous patterns such as ../, absolute paths, drive letters, or symbolic links that point outside the extraction directory. Many secure coding guidelines recommend using canonical path checks rather than manually searching for suspicious substrings, because attackers can hide traversal attempts in unexpected ways. Automated tools can also help identify path traversal risks. Static analysis tools such as SpotBugs or modern IDE security scanners can flag code locations where user-controlled paths are used without validation. These tools would highlight logic similar to the vulnerable version of Plexus Archiver, where the ZIP entry name flowed directly into file creation without safety checks. Incorporating these tools into development pipelines increases the chance of catching such issues before release. 
Finally, developers should assume that any input coming from an external file—such as ZIP metadata—is untrusted. Adding unit tests that include malicious ZIP entries is an effective way to confirm that extraction routines do not allow directory traversal. Testing with intentionally crafted payloads can reveal weaknesses early and reinforce secure extraction practices. 
By consistently validating file paths, using canonical checks, and applying static analysis, developers can prevent path traversal vulnerabilities in archive extraction code and avoid issues like the one seen in Plexus Archiver.

## Conclusion :

The Zip Slip vulnerability in Plexus Archiver occurred because the library trusted file names stored inside ZIP archives and used them without validating where the resulting paths would point. This allowed attackers to include directory traversal sequences such as ../, causing extracted files to be written outside the intended destination folder. The issue demonstrated how a small oversight in path handling can lead to severe security consequences, especially in libraries that are widely used by other tools. The fix introduced in version 3.6.0 added a canonical path check that ensures all extracted files stay within the target directory. By comparing the canonical paths of the destination directory and the file being extracted, the library now prevents malicious ZIP entries from escaping the extraction boundary. This change removes the underlying weakness and restores safe behavior. The case study highlights the importance of validating file paths, treating archive contents as untrusted input, and adopting secure coding practices to prevent similar vulnerabilities in the future.

## References :

**Plexus Archiver Project Page:** 
https://github.com/codehaus-plexus/plexus-archiver 

**Plexus Archiver 3.5 Release (Contains Vulnerable Code):** 
https://github.com/codehaus-plexus/plexus-archiver/releases/tag/plexus-archiver-3.5 

**Plexus Archiver 3.6.0 Release (Contains Fix):** 
https://github.com/codehaus-plexus/plexus-archiver/releases/tag/plexus-archiver-3.6.0 

**CVE-2018-1002200 Entry (Zip Slip):** 
https://www.cve.org/CVERecord?id=CVE-2018-1002200 

**NVD Report for CVE-2018-1002200:** 
https://nvd.nist.gov/vuln/detail/CVE-2018-1002200 

**CWE-22: Improper Limitation of a Pathname to a Restricted Directory (“Path Traversal”):** 
https://cwe.mitre.org/data/definitions/22.html 

**CAPEC-126: Path Traversal:** 
https://capec.mitre.org/data/definitions/126.html

**Snyk Security Research: Zip Slip Vulnerability (Original Disclosure & Explanation):** 
https://security.snyk.io/research/zip-slip-vulnerability

## Contributions :
Originally created by Mrunal Pradeep Patil

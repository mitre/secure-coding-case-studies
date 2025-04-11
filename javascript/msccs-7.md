# MSCCS-7 :: PATH TRAVERSAL IN SALTCORN SERVER

**Introduction:** Insufficient neutralization of user-controllable data used to construct pathnames may allow access to files and directories beyond authorized boundaries. An adversary can exploit such a vulnerability by crafting malicious requests targeting sensitive files and directories, leading to unauthorized data exposure or deletion. The underlying weakness in the source code is consistently listed among the CWE™ Top 25 Most Dangerous Software Weaknesses, ranking 5th in 2024. In October 2024, a vulnerability stemming from this weakness was disclosed in the JavaScript-based Saltcorn server. This case study explores the root cause of the vulnerability, its potential impact, and how the code was ultimately fixed.

**Language:** JavaScript  
**Software:** Saltcorn  
**URL:** https://github.com/saltcorn/saltcorn

**Weakness:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory

The weakness arises when an application utilizes user-controllable data to build a pathname meant to remain within a restricted directory. If the application fails to neutralize navigation commands such as ".." in the input, it may inadvertently allow adversaries to access files in unauthorized areas of the file system. 

Saltcorn is an open source, no-code database application builder. The Saltcorn package contains a `sync` server route responsible for managing data synchronization between the Saltcorn server and clients, ensuring data consistency and handling offline changes efficiently. 

The `sync` route contains one endpoint, `/clean_sync_dir`, that handles POST requests, and the handler is tasked with deleting a directory used for syncing once offline data from the client has been uploaded and synchronized accordingly. However, because the code does not adequately neutralize user-controllable inputs for path traversal commands, the resulting pathname may lead to an unauthorized location differing from the intended syncing directory.

**Vulnerability:** CVE-2024-47818 – Published 7 October 2024  

The weakness in the code originates from the POST request handler for the `/clean_sync_dir` route. The error_catcher() middleware function on line 336 accepts a user-provided request `req` argument and extracts the `dir_name` from the request body on line 337. The code then attempts to construct a pathname `syncDir` on lines 340-345 by joining the potentially tainted `dir_name` to the end of a pre-determined path `rootFolder.location/mobile_app/sync`. The resulting `syncDir` specifies a directory whose contents are to be deleted by calling fs.rm() on line 346.

The join() function used on line 340 performs this construction by combining the individual path segments on lines 341, 342, 343, and 344. It then internally calls the normalize() function to resolve any dot (.) or double dot (..) sequences and to correct path separators to match the target operating system. Unfortunately, join() does not protect against the use of multiple `../` sequences which could be resolved to a location above the rootFolder.

    vulnerable file: packages/server/routes/sync.js
    
    334	router.post(
    335	    "/clean_sync_dir",
    336	    error_catcher(async (req, res) => {
    337	        const { dir_name } = req.body;
    338	        try {
    339	            const rootFolder = await File.rootFolder();
    340	            const syncDir = path.join(
    341	                rootFolder.location,
    342	                "mobile_app",
    343	                "sync",
    344	                dir_name
    345	            );
    346	            await fs.rm(syncDir, { recursive: true, force: true });
    347	            res.status(200).send("");
    348	        } catch (error) {
    349	            getState().log(2, `POST /sync/clean_sync_dir: '${error.message}'`);
    350	            res.status(400).json({ error: error.message || error });
    351	        }
    352	    })
    353	);
    
**Exploit:** CAPEC-126: Path Traversal

An adversary can exploit this weakness by including `../` sequences in `dir_name` to traverse up the server's directory structure, allowing them to specify a path outside the intended confines of `rootFolder.location/mobile_app/sync/`, resulting in the deletion of an unauthorized directory.

The following proof of concept exploit was provided by Saltcorn in its official vulnerability advisory.

    curl -i -X $'POST' \
    -H $'Host: localhost:3000' \
    -H $'Content-Type: application/x-www-form-urlencoded' \
    -H $'Content-Length: 93' \
    -H $'Origin: http://localhost:3000' \
    -H $'Connection: close' \
    -b $'connect.sid=VALID_CONNECT_SID_COOKIE; loggedin=true' \
    --data-binary $'_csrf=VALID_CSRF_VALUE&dir_name=/../../../../../../../../../../tmp/secret' \
    $'http://localhost:3000/sync/clean_sync_dir'

The above provides a `dir_name` value containing `../` sequences that traverse upstream beyond the authorized `rootFolder.location/mobile_app/sync` directory and to the `/tmp/secret` file.

For the exploit above to be successful, the adversary needs a valid session identifier cookie `connect.sid` and a `_csrf` token meant to protect against Cross-Site Request Forgery attacks. These values indicate to the server that any HTTPS request has come from a valid, trusted client, and thus can be trusted. 

One way for an adversary to obtain these values is to leverage the password reset functionality, since such a request typically requires both authentication and CSRF protection. Adversaries can open their browser's developer tools to inspect network requests, trigger the change password functionality, and retrieve the `connect.sid` and `_csrf` values.

Thus, an adversary that controls the POST request is able to exploit this weakness and delete files beyond the intended confines of `rootFolder.location/mobile_app/sync/`, causing data loss or system instability.

**Mitigation:** To fix this issue, a new normalise_in_base() function was created to properly join potentially unsafe path segments to a trusted base and then verify that the resultant path still starts with that trusted base.

Looking at the implementation of this new normalise_in_base() function, line 162 joins the array of unsafe paths to the trusted base. As part of this call to join(), the resulting path is normalized. So far, this is similar to the original code. The important change is on line 165, which checks that the resulting path still resides within the trusted base. If it doesn’t, then a null value is returned on line 166.

    Fixed file: packages/saltcorn-data/models/file.ts
    
    154  static normalise_in_base(
    155    trusted_base: string,
    156    ...unsafe_paths: string[]
    157  ): string | null {
    158    //normalise paths: legacy support for ../files/ paths
    159    const norm_paths = unsafe_paths.map((p) => File.normalise(p));
    160    // combine the paths via path.join() which also normalizes
    161    // traversal sequences
    162    const joined_path = path.join(trusted_base, ...norm_paths);
    163    // validate that the resulting path is still within the trusted
    164    // base
    165    if (joined_path.startsWith(trusted_base)) return joined_path;
    166    else return null;
    167  }

This new normalise_in_base() function was then used within the original error_catcher() middleware function on line 340. The new code on lines 340-342 first joins the trusted segments on line 341 and then passes the resulting trusted base into normalise_in_base() along with the untrusted `dir_name` value.

    Fixed file: packages/server/routes/sync.js
    
    336    error_catcher(async (req, res) => {
    337      const { dir_name } = req.body;
    338      try {
    339        const rootFolder = await File.rootFolder();
    340        const syncDir = File.normalise_in_base(
    341          path.join(rootFolder.location, "mobile_app", "sync"),
    342          dir_name
    343        );
    344        if (syncDir) await fs.rm(syncDir, { recursive: true, force: true });
    348        res.status(200).send("");
    349      } catch (error) {

As previously discussed, normalize_in_base() joins the segments, normalizes the resulting path, and verifies that the path is still within the trusted base, thus removing the weakness from the code.

**Conclusion:** The changes made to the Saltcorn source code prevent malicious sequences such as “../” from causing the creation of a path outside of the desired trusted base. With the weakness resolved, user-controlled input that reaches the error_cather() method can no longer be crafted to cause the deletion of files outside the restricted base path.

**References:**

Saltcorn Project Page: https://github.com/saltcorn/saltcorn

CVE-2018-25088 Entry: https://www.cve.org/CVERecord?id=CVE-2024-47818

CWE-22 Entry: https://cwe.mitre.org/data/definitions/22.html

CAPEC-126 Entry: https://capec.mitre.org/data/definitions/126.html

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-43f3-h63w-p6f6

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2024-47818

Saltcorn Code Commit to Fix Issue: https://github.com/saltcorn/saltcorn/commit/3c551261d0e230635774798009951fa83a07cc3a

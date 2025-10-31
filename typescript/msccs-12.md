# MSCCS-12 :: IMPROPER AUTHENTICATION IN BETTER AUTH

### Introduction:

Applications need to authenticate users to verify that the entity interacting with the application is in fact who they claim to be. Authentication is a critical step when information or functionality should only be available to specific entities. Before any entity's access can be authorized, the entity's identity must be verified. When this verification fails, unintended entities (e.g., an adversary) may be able to access the information or functionality that they are not authorized for. The underlying weakness that leads to improper authentication is annually one of the CWE™ Top 25 Most Dangerous Software Weaknesses, ranking at #13 in 2023 and #14 in 2024. In 2025, such a weakness was discovered by ZeroPath in the API key creation functionality of Better Auth. This case study will examine the weakness, the resulting vulnerability, what it allowed an adversary to accomplish, and how the issue was eventually mitigated.

### Software:

**Name:** Better Auth  
**Language:** TypeScript 
**URL:** https://github.com/better-auth/better-auth

### Weakness:

<a href="https://cwe.mitre.org/data/definitions/303.html">CWE-303: Incorrect Implementation of Authentication Algorithm</a>

The weakness exists when an application incorrectly implements its authentication functionality resulting in unintended execution. In these types of instances, the design is sufficient but there is a mistake made in implementing the design which allows an execution path that is not part of the design.

The mistakes can range from the use of an incorrect operator (e.g., using an 'or' instead of an 'and'), to a typo that changes how a line of code is interpreted, to missing the implementation of a critical step in the algorithm.

### Vulnerability:

<a href="https://www.cve.org/CVERecord?id=CVE-2025-61928">CVE-2025-61928</a> – Published 09 October 2025

Better Auth is framework-agnostic authentication (and authorization) library for TypeScript. It provides a comprehensive set of features out of the box and includes a plugin ecosystem that simplifies adding advanced functionalities with minimal code in short amount of time.

ZeroPath uncovered a critical vulnerability in Better Auth's API keys plugin which has since been fixed. The vulnerability was due to an incorrect implementation of the create key design which allowed adversaries to mint privileged credentials for arbitrary users.

The design of the createApiKey() function defined on line 13 of the create-api-key.ts source code file in Better Auth is intended to only allow local server-based requests to create user keys that give the ability to change certain server-only properties. Any key request from a client that attempts to give permissions to set one of these properties should result in an error and no key being created. Such requests from a client are signaled by a session and access to the headers.

Looking at the vulnerable source code, line 271 sets the authRequired flag to true if two conditions are met. The first is if the authorization context (stored in the variable ctx) has either the request or headers present thus signalling a request from a client. These client-based requests correctly require authorization to set server-only properties after line 282 and hence "authRequired" should be set to True. This is proper implementation of the design to make sure that only authorized users can set server properties.

```diff
vulnerable file: packages/better-auth/src/plugins/api-key/routes/create-api-key.ts

  13  export function createApiKey({
 ...
 270    const session = await getSessionFromCtx(ctx);
-271    const authRequired = (ctx.request || ctx.headers) && !ctx.body.userId;
 272    const user =
 273        session?.user ?? (authRequired ? null : { id: ctx.body.userId });
 274    if (!user?.id) {
 275       throw new APIError("UNAUTHORIZED", {
 276           message: ERROR_CODES.UNAUTHORIZED_SESSION,
 277       });
 278    }
 279
 280    if (authRequired) {
 281       // if this endpoint was being called from the client,
 282       // we must make sure they can't use server-only properties.
```

However, the code added a second condition on line 271 that looked to see if a userId was not provided. When the call comes from the server and no session is present then a userId is provided to state who to create the key for. The vulnerable code incorrectly assumed that the lack of a userId was another indication of a client request and added a check for it.

### Exploit:

<a href="https://capec.mitre.org/data/definitions/115.html">CAPEC-115: Authentication Bypass</a>

An adversary could take advantage of the vulnerable logic by sending a request and providing a userId. The use of the logical AND meant that this would result in "authRequired" being set to false regardless of the outcome of the client session check. The createApiKey() function saves the userId on line 272 using the adversary input and then on line 280 bypasses the validation that stops the privileges for the server-only properties from being assigned to the key.

The end result is that the adversary is able to create an API key with the server-only privileges for any userID that they choose. They can then use this key log into the application as the user and perform tasks that they shouldn't be allowed to perform.

### Fix:

The weakness was fixed by changing the implementation to be more accurate to the design. The first change was to line 271 where the check for userID was removed. This put the focus of the "authRequired" flag soley on the status of the request which was the original intention. The "user" field was also changed online 272-275 to more accurately refelct the status of the session and when the provided userId is used.

```diff
vulnerable file: packages/better-auth/src/plugins/api-key/routes/create-api-key.ts

 270  const session = await getSessionFromCtx(ctx);
-271  const authRequired = (ctx.request || ctx.headers) && !ctx.body.userId;
+271  const authRequired = ctx.request || ctx.headers;
 272  const user =
-273      session?.user ?? (authRequired ? null : { id: ctx.body.userId });
+273      authRequired && !session
+274         ? null
+275         : session?.user || { id: ctx.body.userId };
 276
 277  if (!user?.id) {
 278     throw new APIError("UNAUTHORIZED", {
 279         message: ERROR_CODES.UNAUTHORIZED_SESSION,
 280     });
 281  }
 282
+283  if (session && ctx.body.userId && session?.user.id !== ctx.body.userId) {
+284     	throw new APIError("UNAUTHORIZED", {
+285          message: ERROR_CODES.UNAUTHORIZED_SESSION,
+286      });
+287   }
+288
 289  if (authRequired) {
 290     // if this endpoint was being called from the client,
 291     // we must make sure they can't use server-only properties.
```

The final change was to add a check on line 283 that looks at the user id associated with the current session and the userID provided as input. If they don't match, which would be the case when an adversary is trying to create a key for a targetted user, then an error is thrown on line 284.

### Prevention:

Issues such as this are difficult to catch. The mistake is often only a mistake based on the intention of the design. This is very different from mistakes leading to overflows or injection where the underlying code is clearly in error and allowing functionality that should not be allowed.

Detailed reviews, both peer reviews and independent reivews, can be used to uncover these implementation mistakes. To support these reviews, detailed and accurate code comments that reflect the intended design should be part of the source code. This will help anyone reviewing the code know what is supposed to happen.

In-depth dynamic testing with complete coverage of all user-supplied inputs can also help expose these types of issues. However, to be effective, care must be taken to create test cases that align with the design and expose places where unexpected outcomes are seen. Pen testing type of activites where the testers are given access to the source code can be effective techniques to expose these issues.

Finally, avoiding the urge to "roll your own" libraries instead of leveraging existing and proven code can help avoid these types of weaknesses. Implementation issues eventually surface and existing libraries have ofter experienced and fixed the issues. This is exactly what has happened with Better Auth which is now more sucure since the issue has been fixed.

### Conclusion:

The fix to the implementation to more accurately reflect the intneded design has closed a logic hole that enabled targeted keys to be generated. With the weakness resolved, adversaries can no longer leverage the createApiKey() to create a new key for a target user and then use that key to bypass authorization and gain access to what should have been unauthorized resources.

### References:

Better Auth: https://www.better-auth.com/

Better Auth project site: https://github.com/better-auth/better-auth

ZeroPath Report: https://zeropath.com/blog/breaking-authentication-unauthenticated-api-key-creation-in-better-auth-cve-2025-61928

CVE-2025-61928 Entry: https://www.cve.org/CVERecord?id=CVE-2025-61928

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-99h5-pjcv-gr6v

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2025-61928

CWE-303 Entry: https://cwe.mitre.org/data/definitions/303.html

CAPEC-115 Entry: https://capec.mitre.org/data/definitions/115.html

Better Auth Code Commit to Fix Issue: https://github.com/better-auth/better-auth/commit/556085067609c508f8c546ceef9003ee8c607d39

### Contributions:

Originally created by Drew Buttner - The MITRE Corporation<br>

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a>

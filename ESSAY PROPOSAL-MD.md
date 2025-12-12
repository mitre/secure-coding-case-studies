ESSAY PROPOSAL 

Title:  

Improper Input Validation in Spring Boot  
A short, direct title that clearly identifies the weakness and the software ecosystem involved 
in API request. This even explains the vulnerability that had a critical violation of security.  

Introduction:  

Many Spring Boot applications rely on automatic JSON-to-object binding to map incoming 
requests into Java classes. While this feature simplifies development, it can introduce serious 
security risks when the application binds user input directly to entity classes that contain 
internal fields like admin or some higher attributes in entity may escalate to different. This 
creates opportunities for attackers to manipulate values the developer never intended to 
expose.   

This weakness is tied to CWE categories related to improper input validation and mass 
assignments and happens in several Spring-based projects on this loophole. This case study 
will explore how vulnerability arises, how it can be exploited, and the secure coding practices 
required to prevent it or any technical solution that are upfront for making the security 
violation possible. 

Software:  

Name: Spring Boot   
Language: Java  
URL: https://github.com/spring-projects/spring-boot  

Weakness:  

CWE-915: Improperly Controlled Modification of Dynamically Determined Attributes  
Related: CWE-20 (Improper Input Validation), CWE-522 (Unprotected Fields)  
This weakness occurs when a program allows users to control object attributes that were 
intended to be internal. In frameworks with automatic data binding, such as Spring MVC, an 
attacker can submit JSON fields that match names in an entity class. If the developer has not 
restricted which fields can be updated, the attacker can override protected values and lead to 
big collapse in the entity.  

Generic Example:  

Entity Structure:  
class User {  
public String username;  
public String email;  
public String admin; // sensitive field for admins only   
}  

API End point for Controller class for Json invoke:  

@PostMapping("/update")  
public User update (@RequestBody User user) {  
return userService.save(user);  
}  

A malicious payload:  
{  
“username”: “Sakthi”,  
“email”: “abc@gmail.com”,  
“admin “: “yes”,              / which is only field which is goanna give access for admin  
}

In the above malicious payload, the main security violation for accessing random attributes 
inside an entity is without restriction. Because the binder accepts any matching field, a 
regular user could assign themself to elevated privileges as admin and may get access to 
confidential fields.  

Vulnerability:  

The case study will show actual source code from a selected open-source project 
demonstrating this issue. It will show:  
 The controller is binding directly to an entity and allows modifying the attributes 
directly, even if it's sensitive.  

 Validate at the time of request.  
 Public or modifiable fields that should not be user-controlled or accessed need to 
follow.  
 Why Spring’s frameworks default binder maps allow all matching JSON fields 
without restriction.  
 How the lack of validation or DTO separation led to privilege escalation and 
advantages of accessing attributes without vulnerabilities.  

This section will provide file names, line numbers, and small, focused code excerpts to 
illustrate where the flaw originated and how the copy of entity as DTO will help us not to 
violate and make a security issue. 

Exploit  

CAPEC-234: Privilege Escalation  
The exploit revolves around submitting crafted JSON that includes sensitive fields. For 
example:  

JSON for attributes like admin can either be yes or no or 0/1 (binary) validation.  
{  
“id’': 12,  
“email”: “test123@gmail.com”  
“admin”: "yes" or 1     
} 

If the application binds this directly to an entity or calls it sensible attributes, the attacker 
gains administrative privileges which can lead to accessing many confidential areas inside a 
web application.  

From that point, they could access protected endpoints, modify records, or perform actions 
reserved for administrators and even provide multiple changes and access for users who don’t 
own it.  

Fix:  

The fix section will explain how the vulnerable project resolves the issue and walks through 
the corrected code. The typical secure approach includes:  
• Replacing entity binding with a dedicated DTO (Data transfer Object classes)  
• Validating input using @Valid and Bean Validation annotations.  
• Hiding internal fields using @JsonIgnore not that   
• Rejecting unexpected fields during deserialization and validating each field through 
validators  

Example Fix:  

class UserUpdateDTO {  
public String email;  
}  

@PostMapping("/update")  
public User update (@Valid @RequestBody UserUpdateDTO userUpdateDto) {  
user.setEmail(dto.email);  
return userService.save(user);  
}  

This ensures only explicitly allowed fields can be modified rather than allowing the user to 
use unwanted fields to be accessed and modified.  


DTO gives a clear clone copy of the entity attributes that can be modified but only the 
attributes that can be modified without security violation or end point for attackers to access 
the application through JSON request.  

Prevention:   

Preventing this vulnerability requires a combination of design discipline and proper 
configuration. The case study will emphasize:  

✓ Always using DTOs instead of direct modification on entity class.  
✓ Applying strong validation rules on all incoming data and allowing the DTO creation 
only with the attributes that can be accessed or modified.  
✓ Avoiding public fields in domain models and making the entity private.  
✓ Enabling strict deserialization like - fail-on-unknown-properties=true.   
✓ Conduct periodic security reviews of controller binding behavior and always 
encapsule the private object with getters and setter even for DTO and entities.  
✓ Using static analysis tools that detect mass assignment patterns and follow the proper 
validation rule for security not to be breached.  

Relating each recommendation back to the case study helps readers understand how the issue 
could have been avoided entirely and a proper structure even to use the same function in a 
much safer and secure way allows developer to develop convert and secured application 
without loop of vulnerability or security issues   

Conclusion:

Improper input validation in Spring Boot demonstrates how convenient features, when 
misused, can lead to data tampering and privilege escalation. And explains the biggest issue 
and seriousness of how easy security can be violated in web applications. And explains how 
it causes a serious issue in place of accessing an application with clear examples.  
By introducing DTOs, validating incoming fields, and restricting what parts of a domain 
model can be updated, developers can prevent this class of vulnerabilities. This case study 
will show how an easily overlooked design choice can create major security risks and how 
simple defensive practices can eliminate them without making the structure complex.  
As per my understanding the essay case study give a clear view of what is @RequestBody 
and it function and how that escalates from security o giving attacker easy chance and what 
could be done best to make the application to eliminate vulnerabilities that I figured out. 


References  
Spring Boot Project Page: https://github.com/spring-projects/spring-boot  
Spring Boot Doc: https://docs.spring.io/spring
framework/reference/web/webflux/controller/ann-methods/requestbody.html  
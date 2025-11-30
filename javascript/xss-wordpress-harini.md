 Cross-Site Scripting (XSS) in WordPress Plugins
A Case Study by Harini Dodla (George Mason University)

 Overview
Cross-Site Scripting (XSS) is one of the most common and dangerous vulnerabilities affecting modern websites. It occurs when untrusted user input is displayed on a webpage without proper sanitization or escaping, allowing attackers to inject malicious JavaScript. Since a large percentage of the internet runs on WordPress, even a small vulnerability in a plugin can expose millions of users.

This case study focuses on a real and recurring pattern of XSS issues found in WordPress plugins. Many plugin developers do not consistently use WordPress’s built-in escaping and sanitization functions, creating opportunities for attackers to execute scripts in victims’ browsers. This study explains how XSS happens, demonstrates the impact, and provides actionable recommendations for secure coding.

 Description of the Vulnerability
XSS happens when an application takes user-supplied input (such as a form field, comment, or setting) and outputs it directly into HTML. If the output is not escaped properly, an attacker can inject code like:

html
<script>alert('Hacked!')</script>

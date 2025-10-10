# Secure Coding Case Studies - Style Guide

This style guide is designed to help contributors create high-quality, informative, and consistent secure coding case studies. Following these guidelines will ensure that each case study is based on a relevant issue, is written in a clear and engaging manner, and is effective in educating readers about secure coding practices. Additionally, these guidelines attempt to define a consistent style to the way the case studies are structured and written, further enhancing the ability to deliver an important service to the secure coding community.

## 1. General Principles

- **Clarity and Simplicity**: Write in plain language and avoid unnecessary jargon. Explain technical concepts clearly for readers which may have varying levels of expertise. Expect the reader to not know what something means and try to provide a short explanation or definition of any concepts used. The goal is for the reader not to get lost or confused while reading the case study.
- **Accuracy**: Ensure all technical details, code examples, and recommendations are correct and align with current best practices. A reader will lose interest and trust if there are technical errors with what is being presented.
- **Focus on Security**: Highlight the security implications of the coding practices being discussed. Emphasize the risks of insecure coding, the potential consequences to those leveraging the software, and the benefits of secure alternatives.
- **Actionable Insights**: Provide practical solutions and recommendations that readers can apply in real-world scenarios.

## 2. Selecting A Case Study

The most important step in creating an insightful and interesting case study is the selection of an appropriate real-world incident.

- A case study MUST be about a real publicly disclosed vulnerability in real software. The real-world aspect of the case study provides the strongest possible argument that the type of issue is something that readers should pay attention to. The thinking being that if it happened to this software, then it could happen to my software.
- Select an issue where the source code is available. The purpose of these secure coding case studies is to show the mistake made in the code, how that mistake was exploited, and then how the code was fixed to eliminate the problem. This cannot be explained without access to both the vulnerable and fixed source code. IMPORTANT: Make sure the code is properly licensed to be made public.
- Select an issue that has articles written about how to exploit it. Ideally, these articles even point to actual instances of compromise that can be examined and explained. Pointing to a real exploitation event adds credibility to the importance of the secure coding issue.
- Finally, select an issue that has been fixed and where the patched software is available. The case study should not discuss unpatched or zero-day (i.e., not publicly disclosed) issues.

Once selected, create a new issue within the "Issues" section of the Secure Coding Case Studies GitHub respository. This will help ensure that someone else doesn't propose creating a case study for the same vulnerability. This will also provide a place for others to provide comments and insight related to the proposed case study.

## 3. Case Study Structure

Each case study should follow a consistent structure to ensure readability and logical flow. The order and style are critical to maintain this consistency. Each case study MUST have the following sections in the order presented:

```
1) Title
2) Introduction
3) Software
4) Weakness
5) Vulnerability
6) Exploit
7) Fix
8) Prevention
9) Conclusion
10) References
11) Contributions
```

Each of the above sections is explained in detail below. Please try to follow the guidance as closely as possible.

### _Title_

- Keep it concise and descriptive.
- Avoid overly technical or vague titles.
- Typical title follows the following structure: *\<Weakness/Exploit Type\> In \<Software Name\>*
- Most titles are between 4 and 6 words.

> Examples:
>
> SQL Injection In Postgraas Server\
> Code Injection In Searchor\
> Cross-Site Scripting In OpenC3 COSMOS Server\
> Improper Certificate Validation In Airflow

### _Introduction_

- Briefly introduce the topic and explain why it is important.
- Typical introductions are one paragraph in length.
  - First sentence or two introduces the issue and potential consequences.
  - The next sentence or two introduces the weakness type, potentially mentioning its place in the CWE Top 25
  - This is followed by a sentence introducing the software application
  - The final sentence talks about the scope of the case study.

> Example:
>
> The use of a database to store information is fundamental to many applications. Unfortunately, if the commands to place or retrieve this information are not properly constructed, then an adversary could inappropriately alter or read the information. The underlying source code weakness that makes such attacks possible is annually one of the CWE Top 25 Most Dangerous Software Weaknesses. In 2023 such a vulnerability was disclosed in Blue Yonder postgraas_server. Postgraas offers basic create, read, update, and delete (CRUD) operations for complete PostgreSQL database instances via a simple representational state transfer (REST) application programming interface (API). This case study will look at that vulnerability, the mistake made by the developers, what it enabled an adversary to accomplish, and how the code was eventually corrected.

### _Software_

- This section is used to identify the specific software that the case study is referencing.
- Three different fields are expected.

_Name_

- The name of the software in which the issue existed.
- Include the vendor name if applicable. Do not include the version in this field.

> Examples:
>
> postgraas_server\
> Apache Airflow

_Language_

- The source code language where the root cause weakness was made.

> Examples:
>
> Python\
> JavaScript\
> C\
> C++\
> Java\
> Go

_URL_

- The URL where the software can be found.
- For open source projects this is typically a source repository such as GitHub

> Examples:
>
> https<nolink>://github.com/blue-yonder/postgraas_server\
> https<nolink>://github.com/apache/airflow

### _Weakness_

- This section is used to introduce the type of code level mistake.
- List the relevant CWE identifier and name at the beginning of the section.
- This is not the section to show the vulnerable code, but rather a place to summarize and explain the type of mistake. For example, if the issue is related to an SQL Injection exploit, then use weakness section to explain what improper neutralization is and how this can manipulated by an adversary.
- Typically one to two paragraphs in length.
- The use of generic code examples (i.e., not code the actual code from the vulnerable software, but rather generic code to demonstrate the weakness) is recommended when appropriate to help explain the type of weakness. Please see the section in this style guide related to displaying source code.
- Do not refer to the real software in this section.

> Example:
>
> CWE-89: Improper Neutralization of Special Elements Used in an SQL Command
>
> The weakness exists when software constructs all or part of an SQL command using externally influenced input that has been obtained from an upstream component, but the software does not neutralize (e.g., canonicalize, encode, escape, quote, validate) or incorrectly neutralizes special elements that could modify the intent of the SQL command.
>
> A classic example of this type of weakness is when string concatenation is used to build an SQL command, and untrusted inputs are leveraged from sources like network requests, file data, or user prompts. The example code snippet below shows this weakness ...

### _Vulnerability_

- This section is used to describe the publicly disclosed vulnerability.
- List the relevant CVE identifier at the beginning of the section.
- Next, provide any additional information necessary to introduce the specific real world software and what it is used for. Focus on information that is necessary for the reader to fully understand the vulnerability and its place within the software.
- Then walk the reader through the actual vulnerable code in detail. Call out specific lines and show how the weakness exists. Avoid exploit details as these will go in the next section of the case study.
- Provide the vulnerable source code. (see the Source Code section of this guidance)
- Only include source code that is absolutely necessary in explaining the vulnerability to the reader. Use the triple dot "..." convention to skip multiple lines.
- This is a longer section and should contain as much text as necessary to properly explain the vulnerable source code.

### _Exploit_

- This section is used to describe the how the vulnerability was (or could have been) exploited and what the consequences of the exploit were (or could have been).
- List the relevant CAPEC identifier and name at the beginning of the section.
- Typically one to three paragraphs in length, but complex exploits may take longer to explain and step the reader through.
- When applicable, include example inputs that were used to drive the exploit and show how those inputs took advantage of the weakness in the code. Such code inputs should be highlighted in the same manner as example source code.

> Example:
>
> To exploit this vulnerability an adversary must construct a GET or POST request that contains a crafted “next” parameter. This request would be directed to a web application that uses a vulnerable version of Jupyter Server. Such a request would be the GET URL crafted below:
>
    https://www.example.org/?next=https:///www.malicious_site.com
>This URL — maybe sent via an email to a target user — would appear to come from a trusted application and the target user may be comfortable following the URL for that reason.
>
>Looking closer at the example URL, the value of the “next” parameter would not be compared to the allow_origin due to the lack of a netloc component, and would be passed directly to the redirect() call. The underlying Tornado Web Framework would process the redirect() call and send a response back to the user’s client with a 301 or 302 status code signaling the web client to connect to the malicious URL.

### _Fix_

- This section is used to describe how the original weakness in the source code was fixed.
- Focus only on the changes that are relevant to the weakness being addressed by the case study.
- Provide the fixed source code (see the Source Code section of this guidance) and walk the reader through the changes line by line.
- This section can vary in length depending on how complex the fixed source code is and how many changes had to be made.

### _Prevention_

- This section is used to describe how to prevent similar weaknesses in the future.
- The objective is that a reader will have enough knowledge after reading this section to go implement the suggestions.
- Include well-established secure coding practices that are most effective for this type of weakness.
- Include ways to identify such weaknesses that may have been inadvertently made. This may involve a type of tool to assist and the analysis technique leveraged.
- Try to relate each recommendation back to the case study and how it would have helped prevent the issue.
- Typical prevention sections are a few paragraphs in length.

### _Conclusion_

- Provides a brief summary of the case study.
- Typically one to two paragraphs in length.
- Do not introduce any new information in the Conclusion.

> Example:
>
> The addition of parameterization to the code improves the neutralization efforts and removes the weakness “Improper Neutralization of Special Elements Used in an SQL Command”. With the weakness resolved, user controlled input that reaches the execute() call no longer operates outside of the original intent of the SQL command.

### _References_

- Provide the name and URL of software project page or source repository.
- Provide the name and URL of the CVE item.
- Provide the name and URL of the CWE and CAPEC entries.
- Provide the name and URL of the NVD / OSV vulnerability report if appropriate.
- Provide the name and URL of vendor provided vulnerability report.
- If possible, provide the name and URL of the specific code commit showing the code fix made.
- Provide the name and URL of any article used to help inform the case study.
- If a foundational tutorial or best practice guide is available then provide a URL to this as well.
- Do not list every article or guidance document that is available.

> Examples:
>
> Searchor Project Page: https://github.com/ArjunSharda/Searchor<br>
> CVE-2018-25088 Entry: https://www.cve.org/CVERecord?id=CVE-2023-3364<br>
> CWE-94 Entry: https://cwe.mitre.org/data/definitions/94.html<br>
> CAPEC-242 Entry: https://capec.mitre.org/data/definitions/242.html<br>
> OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-66m2-493m-crh2<br>
> NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2023-3364<br>
> Searchor Code Commit to Fix Issue: https://github.com/ArjunSharda/Searchor/commit/16016506f7bf92b0f21f51841d599126d6fcd15b<br>
> Click and Python: Build Extensible and Composable CLI Apps: https://realpython.com/python-click/<br>
> Searchor-2.4.0-POC-Exploit: https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-<br>
> Python Documentation for ast.literal_eval(): https://docs.python.org/3/library/ast.html#ast.literal_eval

### _Contributions_

- Provides credit to those individuals who significantly contributed to the writing of the case study
- Includes the original creator and any reviewer

> Example:
>
> Originally created by Drew Buttner - The MITRE Corporation\
> Reviewed by David Rothenberg - The MITRE Corporation

## 4. Source Code

When showing source code in a case study, either generic example code or actual vulnerable // fixed code, make sure it is visually separated from the text of the case study. To do this in Markdown use the "code block" formatting option which indents the block and highlights it. A fixed-width font will also be used. A code block is accomplished by preceding each individual line with four spaces.

> Example:
>
> A generic code example would be:
>
    strName = processNetworkRequest()\
    dbCursor = connection.cursor()\
    dbCursor.execute("SELECT * FROM items WHERE owner = '" + strName + "' AND item = 'PrivateData'")\
    result = cursor.fetchall()

> The same highlighting should be used for single line of example code as well.

    SELECT * FROM items WHERE owner = 'Sam' AND item = 'PrivateData'

When presenting actual code from the real world software being used by the case study, incorporate the file name and actual line numbers to help the reader find the source code if they want to explore this code form themself.

> Example:
>
> Looking at the vulnerable source code in postgres_cluster_driver.py, line 22 use ...
> 
    vulnerable file: postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py

    19	def check_db_or_user_exists(db_name, db_user, config):
    20		with _create_pg_connection(config) as con:
    21			with con.cursor() as cur:
    22				cur.execute("SELECT 1 FROM pg_database WHERE datname='{}';".format(db_name))
    23				db_exists = cur.fetchone() is not None

## 5. Images and Diagrams

Images and diagrams should be used as tools to help the reader better understand a complex topic. For example, a diagram that summarizes the different steps involved in an exploit might help the reader better understand a complex topic detailed in the case study text. Typically, case studies have between 0 and 2 images or diagrams. More than 2 may become distracting, but this is not a hard and fast rule.


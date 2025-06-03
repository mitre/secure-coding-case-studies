# Secure Coding Case Studies - Style Guide

This style guide is designed to help contributors create high-quality, informative, and consistent case studies. Following these guidelines will ensure that each case study is clear, consistent, engaging, and effective in educating readers about secure coding practices.

## 1. General Principles

- **Clarity and Simplicity**: Write in plain language and avoid unnecessary jargon. Explain technical concepts clearly for readers with varying levels of expertise. Expect the reader to not know what something means and try to provide a short explanation or definition of any concept used. The goal is for the reader not to get lost or confused while reading the case study.
- **Accuracy**: Ensure all technical details, code examples, and recommendations are correct and align with current best practices. A reader will lose interest and trust if there are technical errors with what is being presented.
- **Focus on Security**: Highlight the security implications of the coding practices being discussed. Emphasize the risks of insecure coding, the potential consequences to those leveraging the software, and the benefits of secure alternatives.
- **Actionable Insights**: Provide practical solutions and recommendations that readers can apply in real-world scenarios.

## 2. Selecting A Case Study

The most important step in creating an insightful and interesting case study is the selection of the real-world incident.

- A case study MUST be about a real vulnerability in real software. The real-world aspect of the case study provides the strongest possible argument that issue is something that reader should pay attention to. The thinking being that if it happened to this software, then it could happen to my software.
- Select an issue where the source code is available. The purpose of these Secure Coding Case Studies is to show the mistake made in the code, how that mistake was exploited, and then how the code was fixed to eliminate the problem. This can not be explained without access to the both the vulnerable and fixed source code. IMPORTANT: Make sure the code is properly licensed to be made public.
- Select an issue that has articles written on how to exploit it. Ideally, these articles even point to actual instances of compromise that can be examined and explained. Showing a real exploitation event adds credibility to the importance of the secure coding issue.
- Finally, select an issue that has been fixed and where the patched software is available. The case study should not discuss unpatched or zero-day (i.e., not publicly known) issues.

## 3. Case Study Structure

Each case study should follow a consistent structure to ensure readability and logical flow.

### _Title_

- Keep it concise and descriptive.
- Avoid overly technical or vague titles.
- Typical title follows the following structure: <weakness/exploit type> In <software name>
- Most titles are between 4 and 6 words.

> [!TIP]
>Examples:
>
>SQL Injection In Postgraas Server\
>Code Injection In Searchor\
>Cross-Site Scripting In OpenC3 COSMOS Server\
>Improper Certificate Validation In Airflow

### _Introduction_

- Briefly introduce the topic and explain why it is important.
- Typical introductions are one paragraph in length.
  - First sentence or two introduces the issue.
  - The next sentence or two introduces the weakness type, potentially mentioning its place in the CWE Top 25
  - This is followed by a sentence introducing the software application
  - The final sentence talks about the scope of the case study.

> [!TIP]
>Example:
>
>The use of a database to store information is fundamental to many applications. Unfortunately, if the commands to place or retrieve this information are not properly constructed, then an adversary could inappropriately alter or read the information. The underlying source code weakness that makes such attacks possible is annually one of the CWE Top 25 Most Dangerous Software Weaknesses. In 2023 such a vulnerability was disclosed in Blue Yonder postgraas_server. Postgraas offers basic create, read, update, and delete (CRUD) operations for complete PostgreSQL database instances via a simple representational state transfer (REST) application programming interface (API). This case study will look at that vulnerability, the mistake made by the developers, what it enabled an adversary to accomplish, and how the code was eventually corrected.

### _Language_

- The source code language where the root cause weakness was made.

> [!TIP]
>Examples:
>
>Python\
>JavaScript\
>C\
>C++\
>Java\
>Go

### _Software_

- The name of the software in which the issue existed.
- Include the vendor name if applicable. Do not include the version in this field.

> [!TIP]
>Examples:
>
>postgraas_server\
>Apache Airflow

### _URL_

- The URL where the software can be found.
- For open source projects this is typically a source repository such as GitHub

> [!TIP]
>Examples:
>
>https<nolink>://github.com/blue-yonder/postgraas_server\
>https<nolink>://github.com/apache/airflow

### _Weakness_

### _Vulnerability_

### _Exploit_

### _Mitigation_

### _Conclusion_

### _References_


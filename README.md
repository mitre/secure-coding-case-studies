# Secure Coding Case Studies

MITRE has a long history in the Software Assurance and Software Vulnerability areas. MITRE founded the Common Vulnerabilities and Exposures (CVE®) effort in 1999 and since has partnered with industry and government leaders to create additional foundational efforts such as the Common Weakness Enumeration (CWE™) and the Common Attack Pattern Enumeration and Classification (CAPEC™).

The case studies presented here leverage MITRE’s decades of experience in source code weakness categorization and reveal detailed information about specific real-world software issues. Our hope is that these case studies provide educators, project leaders, software development teams, and assessment teams insight into these critical issues and show how to avoid them.

With each case study focusing on a real issue in real software, there should be no debate as to the applicability of these mistakes to one’s own day-to-day coding projects. By understanding these issues, the mistakes that were made, and how each was fixed, we will be in a better position to avoid similar problems in the future.

## Definitions

**Neutralization** = A general term to describe the process of ensuring that input or output has certain security properties before it is used. This is independent of the specific protection mechanism that performs the neutralization. The term could refer to one or more of the following: filtering/cleansing, canonicalization/resolution, encoding/decoding, escaping/unescaping, quoting/unquoting, validation, or other mechanisms.

**Tainted** = A state where the contents of an object (i.e., input, data, string) may have been altered or controlled by an adversary and therefore cannot be trusted.

**Weakness** = A condition in a software, firmware, hardware, or service component that, under certain circumstances, could contribute to the introduction of vulnerabilities.

**Vulnerability** = A flaw in a software, firmware, hardware, or service component resulting from a weakness that can be exploited, causing a negative impact to the confidentiality, integrity, or availability of an impacted component or components.

## About MITRE

MITRE is a not-for-profit company that works in the public interest to tackle difficult problems that challenge the safety, stability, security, and well-being of our nation. We operate multiple federally funded research and development centers (FFRDCs), participate in public-private partnerships across national security and civilian agency missions, and maintain an independent technology research program in areas such as artificial intelligence, intuitive data science, quantum information science, health informatics, policy and economic expertise, trustworthy autonomy, cyber threat sharing, and cyber resilience.

MITRE’s approximately 10,000 employees work in the public interest to solve problems for a safer world, with scientific integrity being fundamental to our existence. We are prohibited from lobbying, do not develop or sell products, have no owners or shareholders, and do not compete with industry. Our multidisciplinary teams (including engineers, scientists, data analysts, organizational change specialists, policy professionals, and more) are thus free to pursue the public interest across complex issues from all angles, with no political or commercial pressures to influence our decision-making, technical findings, or policy recommendations.

## Public Release

> [!NOTE]
> Approved for Public Release; Distribution Unlimited. Public Release Case
> Number 23-3938.

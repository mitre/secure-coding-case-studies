# MSCCS-1 :: SQL INJECTION IN POSTGRAAS SERVER
**Introduction:** The use of a database to store information is fundamental to many applications. Unfortunately, if the commands to place or retrieve this information are not properly constructed, then an adversary could inappropriately alter or read the information. The underlying source code weakness that makes such attacks possible is annually one of the CWE™ Top 25 Most Dangerous Software Weaknesses. In 2023 such a vulnerability was disclosed in Blue Yonder postgraas_server. Postgraas offers basic create, read, update, and delete (CRUD) operations for complete PostgreSQL database instances via a simple representational state transfer (REST) application programming interface (API). This case study will look at that vulnerability, the mistake made by the developers, what it enabled an adversary to accomplish, and how the code was eventually corrected.

**Software:** postgraas_server
**Language:** Python
**URL:** https://github.com/blue-yonder/postgraas_server

**Weakness:** CWE-89: Improper Neutralization of Special Elements Used in an SQL Command

The weakness exists when software constructs all or part of an SQL command using externally influenced input that has been obtained from an upstream component, but the software does not neutralize (e.g., canonicalize, encode, escape, quote, validate) or incorrectly neutralizes special elements that could modify the intent of the SQL command.

A classic example of this type of weakness is when string concatenation is used to build an SQL command, and untrusted inputs are leveraged from sources like network requests, file data, or user prompts. The example code snippet shows this weakness, while the example inputs show how the meaning of the command can change.

    strName = processNetworkRequest()
    dbCursor = connection.cursor()
    dbCursor.execute("SELECT * FROM items WHERE owner = '" + strName + "' AND item = 'PrivateData'")
    result = cursor.fetchall()

A provided name of "Sam" will result in the expected SQL command that selects only the private data owned by Sam.

    SELECT * FROM items WHERE owner = 'Sam' AND item = 'PrivateData'

However, a provided name of "x' OR '1=1'--" will result in an SQL command that selects every record in the items table. The OR logic is always TRUE since 1 always equals 1, and hence it does not matter what value is provided for owner. The added -- characters comment out the rest of the line to prevent the additional logic from being applied.

    SELECT * FROM items WHERE owner = 'x' OR '1=1'--' AND item = 'PrivateData'

This resulting SQL command is equivalent to SELECT * FROM items; which is not what the original intention of the command was. By using more complex SQL syntax an adversary could craft a resulting SQL command to achieve a wide variety of objectives.

**Vulnerability:** CVE-2018-25088 – Published 18 July 2023

Looking at the vulnerable source code in postgraas_server, line 22 (line 24 is also vulnerable in the same way) use the Python format() method to insert a string into the SQL statement. The format() method performs a concatenation of a provided value into a template string. No neutralization is performed as part of the format() method. An adversary that can control the value being inserted could use these lines of code to inject malicious SQL into the template string thus manipulating the actions that the SQL statement would perform.

> vulnerable file: postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py
> 
> 19	def check_db_or_user_exists(db_name, db_user, config):
> 20		with _create_pg_connection(config) as con:
> 21			with con.cursor() as cur:
> 22				cur.execute("SELECT 1 FROM pg_database WHERE datname='{}';".format(db_name))
> 23				db_exists = cur.fetchone() is not None
> 24				cur.execute("SELECT 1 FROM pg_roles WHERE rolname='{}';".format(db_user))
> 25				user = cur.fetchone()
> 26				user_exists = user is not None
> 27				return db_exists or user_exists

For this code weakness to be exploitable, the values being inserted (db_name and db_user) must be controllable by the user, also known as tainted input. Looking deeper into the code, the values are obtained from the function parameters defined on line 19. These parameters originate from an untrusted source as part of the database connection arguments provided to the application. This flow of data from the malicious user’s HTTP Request to line 19 is illustrated in the diagram below. The remainder of this section describes this flow in detail.

*POST()*

The data flow into the weakness begins with the handling of a POST request on line 128 of the file management_resources.py. POST requests can be manipulated by an adversary and sent to the postgraas_server as part of an adversary’s exploit — meaning any argument that comes along with the POST request is fully controlled by the adversary.



The db_name and db_username arguments are retrieved on line 139 after being named on lines 136 and 137 respectively. Then on lines 160 and 161 within the same function, each of these arguments is added to the db_credentials object without any validation or modification. No protections are in place to stop an adversary from manipulating the parameters and providing specially crafted db_name and db_username values.
On line 184 the db_credentials object is passed into the create() call to establish the connection with the PostgreSQL database.

*CREATE()*

Following the flow further sees the create() function defined on line 9 of the file _init_.py and the definition of the connection_info object that holds the db_credentials object passed via the code above.



The connection_info object, which now contains the tainted db_name and db_username values, is then passed to the create_postgres_db() call on line 11.

*CREATE_POSTGRES_DB()*

The create_postgres_db() function defined on line 30 in the file postgres_cluster_driver.py receives untrusted db_name and db_username values that were part of the previously defined connection_info object through the connection_dict parameter.

*CHECK_DB_OR_USER_EXISTS()*

These untrusted values are then passed to the vulnerable check_db_or_user_exists() function on line 31 which was previously presented as the vulnerable source code and shown to be subject to SQL Injection.

**Exploit:** CAPEC-66: SQL Injection

In a benign interaction a user would provide an expected name of a database. An example of such a db_name might be:

    annual_sales

The resulting SQL command would be:

    SELECT 1 FROM pg_database WHERE datname='annual_sales'
    
Unfortunately, an adversary interacting with the vulnerable software could send a specially crafted POST request with a malicious db_name argument. In the example exploit that follows, the adversary will leverage the malicious interaction to learn about a specific property of the database that should not be available. Assume the adversary provides the following long and obviously incorrect value for db_name:

    known_database_name' UNION SELECT 1 from pg_database WHERE datistemplate = TRUE --

Doing so would result in the following SQL command after the vulnerable format() concatenation is performed:

    SELECT 1 FROM pg_database WHERE datname='known_database_name' UNION SELECT 1 from pg_database WHERE datistemplate = TRUE --'

When executed, the first WHERE clause will always be true since a known database name was used. The UNION keyword that was injected combines the result from the first SELECT statement to the result of the second SELECT statement. In this case, the second SELECT statement will return true if the datistemplate property of the database is true or will return false if the property is false. Therefore, the complete SQL statement will now return true or false depending on the value of the datistemplate property.

The adversary can learn the true or false result of their manipulated SQL command by monitoring the return from the function and if it claims the database exists or not. If the application says that the database does not exist, then the adversary will know that the datistemplate property is FALSE. If the database does exist, then the adversary can deduce that the datistemplate property is TRUE.

Many techniques exist to generate valid SQL that can cause the SQL engine to alter the makeup of the database, overwrite files on the server, and execute operating system commands. By further manipulating the SQL command, an adversary could perform a wide array of different actions, making this weakness one of the most dangerous.

**Mitigation:** To fix this issue, the format() method was replaced by Psycopg’s built-in parameterization functionality on line 23 to automatically convert Python objects to and from SQL literals.

> fixed file: postgraas_server\backends\postgres_cluster\postgres_cluster_driver.py
> 
> 20	def check_db_or_user_exists(db_name, db_user, config):
> 21		with _create_pg_connection(config) as con:
> 22			with con.cursor() as cur:
> 23				cur.execute("SELECT 1 FROM pg_database WHERE datname='{}';".format(db_name))
> 23				cur.execute("SELECT 1 FROM pg_database WHERE datname=%s;", (db_name, ))
> 24				db_exists = cur.fetchone() is not None
> 25				cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s;", (db_user, ))
> 26				user = cur.fetchone()
> 27				user_exists = user is not None
> 28				return db_exists or user_exists

Parameterization is a well-known tactic to properly neutralize potentially tainted input. Parameterization removes the ability for a malicious value to escape outside of the intended query to create a new query that performs a different task. Parameterization works by separating the values from the queries enabling the SQL engine to enforce values only being used for their intended purpose.

**Conclusion:** The addition of parameterization to the code improves the neutralization efforts and removes the weakness “Improper Neutralization of Special Elements Used in an SQL Command”. With the weakness resolved, user controlled input that reaches the execute() call no longer operates outside of the original intent of the SQL command.

**References:**

postgraas_server Project Page:
https://github.com/blue-yonder/postgraas_server

CVE-2018-25088 Entry:
https://www.cve.org/CVERecord?id=CVE-2018-25088

CWE-89 Entry:
https://cwe.mitre.org/data/definitions/89.html

CAPEC-66 Entry:
https://capec.mitre.org/data/definitions/66.html

OSV Vulnerability Report:
https://osv.dev/vulnerability/GHSA-vghm-8cjp-hjw6

NVD Vulnerability Report:
https://nvd.nist.gov/vuln/detail/CVE-2018-25088

postgraas_server Code Commit to Fix Issue:
https://github.com/blue-yonder/postgraas_server/commit/7cd8d016edc74a78af0d81c948bfafbcc93c937c

Psycopg Documentation Related to Safe Passing of Parameter:
https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries

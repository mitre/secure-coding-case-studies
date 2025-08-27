# MSCCS-9 :: PARAMETER INJECTION IN WHODB

### Introduction:

Improper neutralization of special elements in command logic can lead to severe security vulnerabilities. An adversary can exploit such a vulnerability by injecting malicious parameters into database connection strings, enabling unauthorized access or manipulation of system resources. The underlying weakness in the source code is particularly dangerous in applications that rely on dynamic command construction with user-supplied input. In February 2025, a vulnerability stemming from this weakness was disclosed in the Go-based WhoDB database management system. This case study explores the root cause of the vulnerability, its potential impact, and how the code was ultimately fixed.

### Software:

**Name:** WhoDB  
**Language:** Go  
**URL:** https://github.com/clidey/whodb

### Weakness:

<a href="https://cwe.mitre.org/data/definitions/88.html">CWE-88: Improper Neutralization of Argument Delimiters in a Command</a>

This weakness arises when an application fails to properly neutralize special elements in user-supplied input that are used as argument delimiters in command execution logic. This neutralization entails modifying (e.g., canonicalizing, encoding, escaping, quoting, validating) inputs so that special elements are treated as literal data rather than interpreted as control characters that structure data within commands. The following is a simple example of an application constructing a MongoDB connection URI in Go:

    func connectToDatabase(userInput string) {
        connectionURI := "mongodb://localhost:27017/?authSource=" + userInput
        client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(connectionURI))
    
        // Perform database operations...
    }

The function parameter `userInput` is passed into the function, and no validation or escaping is performed before its used to build the connectionURI on the second line. Thus, an adversary could inject arbitrary parameters into the connection URI by including the delimiter `&` as part of the input. For example, if the adversary inputs the string `admin&ssl=false`, then the resulting connection URI would be:

    mongodb://localhost:27017/?authSource=admin&ssl=false

The injected `ssl=false` parameter would disable SSL and potentially expose sensitive data in transit or allow the interception of unencrypted database traffic.

### Vulnerability:

<a href="https://www.cve.org/CVERecord?id=CVE-2025-24787">CVE-2025-24787</a> – Published 6 February 2025 

WhoDB is a Go-based database management system that utilizes several libraries to connect drivers to database servers, like Elasticsearch, PostgreSQL, and MySQL. Because each of these drivers requires the construction of database connection URIs based on user input, improper handling of these inputs could lead to unintended behavior. WhoDB is meant to simplify the process and control which settings are made available to keep the database connection within the desired security bounds.

The vulnerability in the WhoDB code arises from inadequate input validation in the construction of the database connection URI. This case study focuses on the MySQL connection, which is set up via the function DB() on line 22 of the source code file `mysql/db.go`. This function is responsible for establishing the connection to a MySQL database using GORM, an object-relational mapping (ORM) library for Go. The parameter `config` is passed into the function on line 22 and contains the user-provided database connection values, which are then extracted from `config.Credentials.Advanced` on lines 23-39. No validation is performed on any of the inputs received.

    vulnerable file: core/src/plugins/mysql/db.go
    
    22    func DB(config *engine.PluginConfig) (*gorm.DB, error) {
    23        port := common.GetRecordValueOrDefault(config.Credentials.Advanced, portKey, "3306")
    24        charset := common.GetRecordValueOrDefault(config.Credentials.Advanced, charsetKey, "utf8mb4")
    25        parseTime := common.GetRecordValueOrDefault(config.Credentials.Advanced, parseTimeKey, "True")
    26        loc := common.GetRecordValueOrDefault(config.Credentials.Advanced, locKey, "Local")
    27        allowClearTextPasswords:=common.GetRecordValueOrDefault(config.Credentials.Advanced,allowClearTextPasswordsKey,"0")
    28        hostPath := common.GetRecordValueOrDefault(config.Credentials.Advanced, hostPathKey, "/")
    29
    30        params := url.Values{}
    31
    32        for _, record := range config.Credentials.Advanced {
    33            switch record.Key {
    34            case portKey, charsetKey, parseTimeKey, locKey, allowClearTextPasswordsKey, hostPathKey:
    35                continue
    36            default:
    37                params.Add(record.Key, fmt.Sprintf("%v", record.Value))
    38            }
    39        }
    40
    41      dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)%v%v?charset=%v&parseTime=%v&loc=%v&allowCleartextPasswords=%v&%v",
                               config.Credentials.Username,
                               config.Credentials.Password,
                               config.Credentials.Hostname,
                               port,
                               hostPath,
                               config.Credentials.Database,
                               charset,
                               parseTime,
                               loc,
                               allowClearTextPasswords,
                               params.Encode())
    42      db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
    43      if err != nil {
    44          return nil, err
    45      }
    46      return db, nil

On line 41, the Data Source Name (DSN) string is constructed using the retrieved configuration values without any input validation (e.g. escaping or encoding of special characters), thus allowing users to inject arbitrary parameters into the URI string.

The MySQL database connection is then opened on line 42, and the database connection object `db` is then returned on line 46.

### Exploit:

<a href="https://capec.mitre.org/data/definitions/137.html">CAPEC-137: Parameter Injection</a>

Users normally interact with WhoDB by sending HTTP requests with the desired values to connect to a database. However, an adversary can exploit the vulnerability by injecting additional parameters into the HTTP request and manipulating any of the connection values. For example, instead of providing an expected loc value of `Local`, an adversary could provide a loc value of `Local&allowAllFiles=true`. The ‘&’ character acts as a field delimiter and enables the adversary to append another connection value as they desire. In the example input above, the parameter `allowAllFiles` is added and the connecting string that results is as follows:

    root:password@tcp(mysql:3306)/mysql?charset=utf8&parseTime=True&loc=Local&allowAllFiles=true&allowCleartextPasswords=0

The `AllowAllFiles` configuration flag determines whether the client application (in this case, WhoDB) is allowed to access any file on its local filesystem or only files that have been explicitly registered. In other words, setting `AllowAllFiles` equal to true disables the known good check when loading files via a `LOAD DATA LOCAL INFILE` query. The `LOAD DATA LOCAL INFILE` query in MySQL is typically used to perform bulk imports of data specified files located on the client machine into a database table. However, if improperly configured with the `AllowAllFiles` flag set to `true`, it can be abused to exfiltrate sensitive files (like `/etc/passwd`) from the client machine running WhoDB to an adversary-controlled MySQL server.

Using the connection that was just established, the adversary can create a new table in their database and enable (via the global setting `local_infile`) the loading of files from the local client into this table.

    CREATE TABLE temp_storage (
        line TEXT
    );
    SET GLOBAL local_infile=1;

A `LOAD DATA LOCAL INFILE` query can then be used as previously discussed to read the contents of a sensitive file like `/etc/passwd` into the `temp_storage` table.

    LOAD DATA LOCAL INFILE '/etc/passwd'
    INTO TABLE temp_storage
    FIELDS TERMINATED BY '\0'
    LINES TERMINATED BY '\n';

Once the local file has been copied into the table, the adversary can then query the `temp_storage` table to view the contents of the file.

### Fix:

To fix this issue, several input validation measures were added to the source code that constructs the DSN string. The first change was the implementation of the ParseConnectionConfig() function containing these checks in a new file grom\db.go.

On line 65 the user-provided value for the port number is first converted to an integer using Go’s `strconv.Atoi` method, returning an error in case the value is not an integer. Inputs for parameters specific to MySQL are then validated beginning on line 71 with the user-provided value for the `parseTime` parameter being constrained to specific Boolean-like values (i.e., 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, and False) using the builtin Go method `strconv.ParseBool`, returning an error on any other value. On line 75, the user-provided value for the location is constrained by using the builtin Go method `time.LoadLocation`, returning an error if the location value does not correspond to a valid time zone. On line 79, the `strconv.ParseBool` method is used again to constrain the user-provided `allowClearTextPasswords` parameter to Boolean-like values, returning an error otherwise. On line 90, the `strconv.Atoi` method is used again to ensure that the user-provided connection timeout value is an integer, returning an error otherwise. Finally, on lines 96-99, `url.PathEscape` is used to encode special characters in the username, password, database, and hostname fields so that they are safe for use in URLs and queries.

All of these configuration details, which have been provided by the user via the config parameter have now gone through input validation, are stored in the `input` variable on line 95.

    new file: core\src\plugins\gorm\db.go
    
    63    func (p *GormPlugin) ParseConnectionConfig(config *engine.PluginConfig) (*ConnectionInput, error) {
    64        //common
    65        port, err := strconv.Atoi(common.GetRecordValueOrDefault(config.Credentials.Advanced, portKey, "3306"))
    66        if err != nil {
    67            return nil, err
    68        }
    69
    70        //mysql/mariadb specific
    71        parseTime, err := strconv.ParseBool(common.GetRecordValueOrDefault(config.Credentials.Advanced, parseTimeKey, "True"))
    72        if err != nil {
    73            return nil, err
    74        }
    75        loc, err := time.LoadLocation(common.GetRecordValueOrDefault(config.Credentials.Advanced, locKey, "Local"))
    76        if err != nil {
    77            return nil, err
    78        }
    79        allowClearTextPasswords, err := strconv.ParseBool(common.GetRecordValueOrDefault(config.Credentials.Advanced, allowClearTextPasswordsKey, "0"))
    80        if err != nil {
    81            return nil, err
    82        }
    ...
    90        connectionTimeout, err := strconv.Atoi(common.GetRecordValueOrDefault(config.Credentials.Advanced, connectionTimeoutKey, "90"))
    91        if err != nil {
    92            return nil, err
    93        }
    94
    95        input := &ConnectionInput{
    96            Username:                url.PathEscape(config.Credentials.Username),
    97            Password:                url.PathEscape(config.Credentials.Password),
    98            Database:                url.PathEscape(config.Credentials.Database),
    99            Hostname:                url.PathEscape(config.Credentials.Hostname),
    100           Port:                    port,
    101           ParseTime:               parseTime,
    102           Loc:                     loc,
    103           AllowClearTextPasswords: allowClearTextPasswords,
    ...
    108           ConnectionTimeout:       connectionTimeout,
    109       }


One last bit of input validation is performed before being returned for use. In the original vulnerable code, any custom parameters were added to `params` without validation. The new code passes these additional parameters to the builtin Go method `url.QueryEscape` on line 119, which escapes input to ensure that parameters can be safely placed inside a URL query. These parameters are then stored in the `input.ExtraOptions` field on 122.

With all input properly validated, the `input` variable is returned on line 125 for use by the original MySQL connection.

    new file: core\src\plugins\gorm\db.go
    
    111        // if this config is a pre-configured profile, then allow reading of additional params
    112        if config.Credentials.IsProfile {
    113            params := make(map[string]string)
    114            for _, record := range config.Credentials.Advanced {
    115                switch record.Key {
    116                    case portKey, parseTimeKey, locKey, allowClearTextPasswordsKey, sslModeKey, httpProtocolKey, readOnlyKey, debugKey, connectionTimeoutKey:
    117                        continue
    118                    default:
    119                        params[record.Key] = url.QueryEscape(record.Value) // todo: this may break for postgres
    120                }
    121            }
    122            input.ExtraOptions = params
    123        }
    124
    125        return input, nil
    126    }

On line 27 of the fixed mysql/db.go file, a call to the previously-defined ParseConnectionConfig() function is added to validate all the configuration details provided in the `config` parameter. A mysqlConfig struct is then instantiated on line 32, and the information from `connectionInput` is copied into it on lines 33-41. Lastly, instead of manually concatenating parameters to the DSN string as done in the vulnerable code, the `mysqlConfig.FormatDSN` method is used on line 43 to securely format the previously created `mysqlConfig` struct into a valid DSN.

The database connection object `db` is then returned on line 47.

    fixed file: core/src/plugins/mysql/db.go
    
    26    func (p *MySQLPlugin) DB(config *engine.PluginConfig) (*gorm.DB, error) {
    27        connectionInput, err := p.ParseConnectionConfig(config)
    28        if err != nil {
    29            return nil, err
    30        }
    31
    32        mysqlConfig := mysqldriver.NewConfig()
    33        mysqlConfig.User = connectionInput.Username
    34        mysqlConfig.Passwd = connectionInput.Password
    35        mysqlConfig.Net = "tcp"
    36        mysqlConfig.Addr = net.JoinHostPort(connectionInput.Hostname, strconv.Itoa(connectionInput.Port))
    37        mysqlConfig.DBName = connectionInput.Database
    38        mysqlConfig.AllowCleartextPasswords = connectionInput.AllowClearTextPasswords
    39        mysqlConfig.ParseTime = connectionInput.ParseTime
    40        mysqlConfig.Loc = connectionInput.Loc
    41        mysqlConfig.Params = connectionInput.ExtraOptions
    42
    43        db, err := gorm.Open(mysql.Open(mysqlConfig.FormatDSN()), &gorm.Config{})
    44        if err != nil {
    45            return nil, err
    46        }
    47        return db, nil
    48    }

Validating inputs supplied by the user ensures that arbitrary parameters are not injected into the connection URI, thus removing the weakness from the code. Similar changes were implemented in the URI constructions for other database drivers used by WhoDB.

### Conclusion:

The addition of input validation to the WhoDB source code prevents arbitrary parameter injection, which previously led to local file inclusion and consequent exfiltration of sensitive files. With the weakness resolved, user-controlled input is eliminated as an attack vector via the database connection strings.

### References:

WhoDB Project Page: https://github.com/clidey/whodb  

CVE-2025-24787 Entry: https://www.cve.org/CVERecord?id=CVE-2025-24787  

CWE-88 Entry: https://cwe.mitre.org/data/definitions/88.html  

CAPEC-137 Entry: https://capec.mitre.org/data/definitions/137.html  

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-c7w4-9wv8-7x7c  

WhoDB Code Commit to Fix Issue: https://github.com/clidey/whodb/commit/8d67b767e00552e5eba2b1537179b74bfa662ee1

### Contributions:

Originally created by Mark Tran - The MITRE Corporation<br>
Reviewed by Travis Aldrich - The MITRE Corporation<br>
Reviewed by Drew Buttner - The MITRE Corporation

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a>
NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2025-24787  

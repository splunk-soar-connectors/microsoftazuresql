[comment]: # "Auto-generated SOAR connector documentation"
# Microsoft Azure SQL

Publisher: Splunk  
Connector Version: 2\.1\.6  
Product Vendor: Microsoft  
Product Name: Azure SQL  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports investigative actions against a Microsoft Azure SQL Server

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Establishing a Connection to your Azure SQL Server

Prior to configuring your Azure SQL asset, you must install the **ODBC driver** on your Phantom
instance. This can be done by running the following commands on your instance under a user with root
privileges:

-   ODBC Driver 17 Installation

      

    -   sudo su
    -   If using Centos7/RedHat7: curl https://packages.microsoft.com/config/rhel/7/prod.repo \>
        /etc/yum.repos.d/mssql-release.repo
    -   If using Centos6/RedHat6: curl https://packages.microsoft.com/config/rhel/6/prod.repo \>
        /etc/yum.repos.d/mssql-release.repo
    -   If using a different OS, check
        [here](https://docs.microsoft.com/en-us/sql/connect/odbc/linux-mac/installing-the-microsoft-odbc-driver-for-sql-server?view=sql-server-2017)
    -   exit
    -   sudo yum install msodbcsql17

After installing the Microsoft Azure SQL app and ODBC driver, you have two options to configure your
asset:

-   Fill out every asset field except for the Custom Connection String box
-   Use a Custom Connection String. Example format:
    -   Driver={ODBC Driver 17 for SQL
        Server};Server=tcp:test-server.database.windows.net;Database=sampledb;Uid=username;Pwd=password;Encrypt=no;TrustServerCertificate=yes;Trusted_Connection=yes;Connection
        Timeout=30;

## MIT

This app uses the pyodbc module, which is licensed under the MIT License, Copyright (c) 2019, The
Python ODBC Team.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Azure SQL asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  optional  | string | Username
**password** |  optional  | password | Password
**host** |  optional  | string | Server or IP Address
**database** |  optional  | string | Database
**driver** |  optional  | string | ODBC Driver for SQL Server
**trust\_server** |  optional  | boolean | Trust Server Certificate
**connection\_string** |  optional  | password | Custom Connection String

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list tables](#action-list-tables) - Lists all the tables in the database connected to your asset  
[list columns](#action-list-columns) - Lists all the columns of a table existing within the database connected to your asset  
[run query](#action-run-query) - Run a query against a table or tables in the database  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list tables'
Lists all the tables in the database connected to your asset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**table\_schema** |  optional  | Returns the tables only belonging to this schema | string |  `azuresql table schema` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.table\_schema | string |  `azuresql table schema` 
action\_result\.data\.\*\.TABLE\_CATALOG | string |  `azuresql table catalog` 
action\_result\.data\.\*\.TABLE\_NAME | string |  `azuresql table name` 
action\_result\.data\.\*\.TABLE\_SCHEMA | string |  `azuresql table schema` 
action\_result\.summary\.num\_tables | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list columns'
Lists all the columns of a table existing within the database connected to your asset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**table\_name** |  required  | Returns the columns belonging to this table | string |  `azuresql table name` 
**table\_schema** |  optional  | Table Schema | string |  `azuresql table schema` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.table\_name | string |  `azuresql table name` 
action\_result\.parameter\.table\_schema | string |  `azuresql table schema` 
action\_result\.data\.\*\.COLUMN\_NAME | string | 
action\_result\.data\.\*\.TABLE\_NAME | string |  `azuresql table name` 
action\_result\.summary\.num\_columns | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Run a query against a table or tables in the database

Type: **generic**  
Read only: **False**

It is recommended to use the <b>format\_vars</b> parameter when applicable\. For example, if you wanted to find a specific IP, you could set <b>query</b> to a formatted string, like "select \* from my\_hosts where ip = ?" \(note the use of <b>?</b>\), and set <b>format\_vars</b> to the IP address\. This will ensure the inputs are safely sanitized and avoid SQL injection attacks\.<br>Setting <b>no\_commit</b> will make it so the App does not commit any changes made to the database \(so you can ensure it's a read\-only query\)\.<br><br>The <b>format\_vars</b> parameter accepts a comma\-separated string\. You can escape commas by surrounding them in double quotes, and escape double quotes with a backslash\. Assuming you have a list of values for the format vars, you can employ this code in your playbooks to properly format it into a string\:<br> <code>format\_vars\_str = ','\.join\(\['"\{\}"'\.format\(str\(x\)\.replace\('\\\\', '\\\\\\\\'\)\.replace\('"', '\\\\"'\)\) for x in format\_vars\_list\]\)</code>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query string | string |  `sql query` 
**format\_vars** |  optional  | Comma separated list of variables | string | 
**no\_commit** |  optional  | Do not commit changes to the Database | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.format\_vars | string | 
action\_result\.parameter\.no\_commit | boolean | 
action\_result\.parameter\.query | string |  `sql query` 
action\_result\.data\.\*\.CategoryName | string | 
action\_result\.data\.\*\.ProductName | string | 
action\_result\.summary\.num\_rows | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
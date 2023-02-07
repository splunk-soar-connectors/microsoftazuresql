[comment]: # "Auto-generated SOAR connector documentation"
# Microsoft Azure SQL

Publisher: Splunk  
Connector Version: 3\.0\.0  
Product Vendor: Microsoft  
Product Name: Azure SQL  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

This app supports investigative actions against a Microsoft Azure SQL Server

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
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
## Proxy Details

This app will ignore the HTTP_PROXY and HTTPS_PROXY environment variables, as it does not use HTTP
to connect to the database. Below are the default ports used by Microsoft-Azure-Sql.

## Port Details

Below are the default ports used by this app.

| Service Name                    | Transport Protocol | Port |
|---------------------------------|--------------------|------|
| Microsoft-SQL-Server (ms-sql-s) | tcp                | 1433 |
| Microsoft-SQL-Server (ms-sql-s) | udp                | 1433 |

## LGPL

This app uses the pymssql module, which is licensed under the Free Software Foundation (FSF).


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Azure SQL asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | Username
**password** |  required  | password | Password
**host** |  required  | string | Server \(example\: example\.database\.windows\.net\)
**database** |  required  | string | Database

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
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.table\_schema | string |  `azuresql table schema`  |   dbo 
action\_result\.data\.\*\.TABLE\_CATALOG | string |  `azuresql table catalog`  |   sampledb 
action\_result\.data\.\*\.TABLE\_NAME | string |  `azuresql table name`  |   Customer  BuildVersion 
action\_result\.data\.\*\.TABLE\_SCHEMA | string |  `azuresql table schema`  |   SalesLT 
action\_result\.summary\.num\_tables | numeric |  |   12  2 
action\_result\.message | string |  |   Successfully listed tables  Num tables\: 12 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 
action\_result\.data\.\*\.TABLE\_TYPE | string |  |   TEST TABLE   

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
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.table\_name | string |  `azuresql table name`  |   vProductModelCatalogDescription 
action\_result\.parameter\.table\_schema | string |  `azuresql table schema`  |   SalesLT 
action\_result\.data\.\*\.COLUMN\_NAME | string |  |   ProductModelID 
action\_result\.data\.\*\.TABLE\_NAME | string |  `azuresql table name`  |   vProductModelCatalogDescription 
action\_result\.summary\.num\_columns | numeric |  |   25 
action\_result\.message | string |  |   Num columns\: 25 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 
action\_result\.data\.\*\.DATA\_TYPE | string |  |   int 
action\_result\.data\.\*\.DOMAIN\_NAME | string |  `domain`  |  
action\_result\.data\.\*\.IS\_NULLABLE | string |  |   YES 
action\_result\.data\.\*\.TABLE\_SCHEMA | string |  |   sampledbo 
action\_result\.data\.\*\.DOMAIN\_SCHEMA | string |  `sampledomain`  |  
action\_result\.data\.\*\.NUMERIC\_SCALE | numeric |  |   0 
action\_result\.data\.\*\.TABLE\_CATALOG | string |  |   sampledb 
action\_result\.data\.\*\.DOMAIN\_CATALOG | string |  `domain`  |  
action\_result\.data\.\*\.ORDINAL\_POSITION | numeric |  |   1 
action\_result\.data\.\*\.NUMERIC\_PRECISION | numeric |  |   10 
action\_result\.data\.\*\.NUMERIC\_PRECISION\_RADIX | numeric |  |   10   

## action: 'run query'
Run a query against a table or tables in the database

Type: **generic**  
Read only: **False**

It is recommended to use the <b>format\_vars</b> parameter when applicable\. For example, if you wanted to find a specific IP, you could set <b>query</b> to a formatted string, like \\"select \* from my\_hosts where ip = %s\\" \(note the use of %s\), and set <b>format\_vars</b> to the IP address\. This will ensure the inputs are safely sanitized and to avoid SQL injection attacks\. Regardless of the type of input it's expecting, the only format specifier which should be used is %s\.<br>Setting <b>no\_commit</b> will make it so the App does not commit any changes made to the database \(so you can ensure it's a read\-only query\)\.<br><br>The <b>format\_vars</b> parameter accepts a comma\-separated list\. You can escape commas by surrounding them in double quotes, and escape double quotes with a backslash\. Assuming you have a list of values for the format vars, you can employ this code in your playbooks to properly format it into a string\:<br> <code>format\_vars\_str = ','\.join\(\['\\"\{\}\\"'\.format\(str\(x\)\.replace\('\\\\\\\\', '\\\\\\\\\\\\\\\\'\)\.replace\('\\"', '\\\\\\\\\\"'\)\) for x in format\_vars\_list\]\)</code>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query string | string |  `sql query` 
**format\_vars** |  optional  | Comma separated list of variables | string | 
**no\_commit** |  optional  | Do not commit changes to the Database | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.format\_vars | string |  |   a 
action\_result\.parameter\.no\_commit | boolean |  |   True  False 
action\_result\.parameter\.query | string |  `sql query`  |   SELECT TOP 20 pc\.Name as CategoryName, p\.name as ProductName FROM \[SalesLT\]\.\[ProductCategory\] pc JOIN \[SalesLT\]\.\[Product\] p ON pc\.productcategoryid = p\.productcategoryid 
action\_result\.data\.\*\.CategoryName | string |  |   Test Frames 
action\_result\.data\.\*\.ProductName | string |  |   Test Frame \- Black, 58 
action\_result\.summary\.num\_rows | numeric |  |   20 
action\_result\.message | string |  |   Num rows\: 20 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 
action\_result\.data\.\*\.Status | string |  |  
# Microsoft Azure SQL

Publisher: Splunk \
Connector Version: 3.0.2 \
Product Vendor: Microsoft \
Product Name: Azure SQL \
Minimum Product Version: 6.3.0

This app supports investigative actions against a Microsoft Azure SQL Server

## Proxy Details

This app will ignore the HTTP_PROXY and HTTPS_PROXY environment variables, as it does not use HTTP
to connect to the database. Below are the default ports used by Microsoft-Azure-Sql.

## Port Details

Below are the default ports used by this app.

| Service Name | Transport Protocol | Port |
|---------------------------------|--------------------|------|
| Microsoft-SQL-Server (ms-sql-s) | tcp | 1433 |
| Microsoft-SQL-Server (ms-sql-s) | udp | 1433 |

## LGPL

This app uses the pymssql module, which is licensed under the Free Software Foundation (FSF).

### Configuration variables

This table lists the configuration variables required to operate Microsoft Azure SQL. These variables are specified when configuring a Azure SQL asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** | required | string | Username |
**password** | required | password | Password |
**host** | required | string | Server (example: example.database.windows.net) |
**database** | required | string | Database |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[list tables](#action-list-tables) - Lists all the tables in the database connected to your asset \
[list columns](#action-list-columns) - Lists all the columns of a table existing within the database connected to your asset \
[run query](#action-run-query) - Run a query against a table or tables in the database

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'list tables'

Lists all the tables in the database connected to your asset

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**table_schema** | optional | Returns the tables only belonging to this schema | string | `azuresql table schema` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.table_schema | string | `azuresql table schema` | dbo |
action_result.data.\*.TABLE_CATALOG | string | `azuresql table catalog` | sampledb |
action_result.data.\*.TABLE_NAME | string | `azuresql table name` | Customer BuildVersion |
action_result.data.\*.TABLE_SCHEMA | string | `azuresql table schema` | SalesLT |
action_result.summary.num_tables | numeric | | 12 2 |
action_result.message | string | | Successfully listed tables Num tables: 12 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.TABLE_TYPE | string | | TEST TABLE |

## action: 'list columns'

Lists all the columns of a table existing within the database connected to your asset

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**table_name** | required | Returns the columns belonging to this table | string | `azuresql table name` |
**table_schema** | optional | Table Schema | string | `azuresql table schema` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.table_name | string | `azuresql table name` | vProductModelCatalogDescription |
action_result.parameter.table_schema | string | `azuresql table schema` | SalesLT |
action_result.data.\*.COLUMN_NAME | string | | ProductModelID |
action_result.data.\*.TABLE_NAME | string | `azuresql table name` | vProductModelCatalogDescription |
action_result.summary.num_columns | numeric | | 25 |
action_result.message | string | | Num columns: 25 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.DATA_TYPE | string | | int |
action_result.data.\*.DOMAIN_NAME | string | `domain` | |
action_result.data.\*.IS_NULLABLE | string | | YES |
action_result.data.\*.TABLE_SCHEMA | string | | sampledbo |
action_result.data.\*.DOMAIN_SCHEMA | string | `sampledomain` | |
action_result.data.\*.NUMERIC_SCALE | numeric | | 0 |
action_result.data.\*.TABLE_CATALOG | string | | sampledb |
action_result.data.\*.DOMAIN_CATALOG | string | `domain` | |
action_result.data.\*.ORDINAL_POSITION | numeric | | 1 |
action_result.data.\*.NUMERIC_PRECISION | numeric | | 10 |
action_result.data.\*.NUMERIC_PRECISION_RADIX | numeric | | 10 |

## action: 'run query'

Run a query against a table or tables in the database

Type: **generic** \
Read only: **False**

It is recommended to use the <b>format_vars</b> parameter when applicable. For example, if you wanted to find a specific IP, you could set <b>query</b> to a formatted string, like \\"select * from my_hosts where ip = %s\\" (note the use of %s), and set <b>format_vars</b> to the IP address. This will ensure the inputs are safely sanitized and to avoid SQL injection attacks. Regardless of the type of input it's expecting, the only format specifier which should be used is %s.<br>Setting <b>no_commit</b> will make it so the App does not commit any changes made to the database (so you can ensure it's a read-only query).<br><br>The <b>format_vars</b> parameter accepts a comma-separated list. You can escape commas by surrounding them in double quotes, and escape double quotes with a backslash. Assuming you have a list of values for the format vars, you can employ this code in your playbooks to properly format it into a string:<br> <code>format_vars_str = ','.join(['\\"{}\\"'.format(str(x).replace('\\\\\\\\', '\\\\\\\\\\\\\\\\').replace('\\"', '\\\\\\\\\\"')) for x in format_vars_list])</code>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Query string | string | `sql query` |
**format_vars** | optional | Comma separated list of variables | string | |
**no_commit** | optional | Do not commit changes to the Database | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.format_vars | string | | a |
action_result.parameter.no_commit | boolean | | True False |
action_result.parameter.query | string | `sql query` | SELECT TOP 20 pc.Name as CategoryName, p.name as ProductName FROM [SalesLT].[ProductCategory] pc JOIN [SalesLT].[Product] p ON pc.productcategoryid = p.productcategoryid |
action_result.data.\*.CategoryName | string | | Test Frames |
action_result.data.\*.ProductName | string | | Test Frame - Black, 58 |
action_result.summary.num_rows | numeric | | 20 |
action_result.message | string | | Num rows: 20 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.data.\*.Status | string | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

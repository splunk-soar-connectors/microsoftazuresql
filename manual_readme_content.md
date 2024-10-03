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

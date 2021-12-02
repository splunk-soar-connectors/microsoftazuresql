[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
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

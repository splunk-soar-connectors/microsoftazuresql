# File: microsoftazuresql_connector.py
#
# Copyright (c) 2019-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import binascii
import csv
import datetime
import json
import struct
import sys

import phantom.app as phantom
import pymssql
import requests
from bs4 import BeautifulSoup
from dateutil.tz import tzoffset
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from microsoftazuresql_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MicrosoftAzureSqlConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MicrosoftAzureSqlConnector, self).__init__()
        self._state = None

    def _initialize_error(self, msg, exception=None):
        if self.get_action_identifier() == "test_connectivity":
            self.save_progress(msg)
            if exception:
                self.save_progress(str(exception))
            self.set_status(phantom.APP_ERROR, "Test Connectivity Failed")
        else:
            self.set_status(phantom.APP_ERROR, msg, exception)
        return phantom.APP_ERROR

    def _dump_error_log(self, error, message="Exception occurred."):
        self.error_print(message, dump_object=error)

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200 or response.status_code == 202:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(error_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', '') or 'text/javascript' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_message = MSAZURESQL_ERROR_MESSAGE_UNAVAILABLE
        self._dump_error_log(e)
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as ex:
            self._dump_error_log(ex, "Error occurred while fetching exception information")

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_message)

        return error_text

    def _bytes_to_date(self, binary_str):
        unpacked = struct.unpack('QIhH', binary_str)
        m = []
        for tup in unpacked:
            m.append(tup)

        days = m[1]
        microseconds = m[0] / 10 if m[0] else 0

        timezone = m[2]
        tz = tzoffset('ANY', timezone * 60)
        date = datetime.datetime(*[1900, 1, 1, 0, 0, 0], tzinfo=tz)
        td = datetime.timedelta(days=days, minutes=m[2], microseconds=microseconds)
        date += td
        return date

    def _get_query_results(self, action_result):

        try:
            results = []
            columns = self._cursor.description
            summary = action_result.update_summary({})
            if columns:
                for value in self._cursor.fetchall():
                    column_dict = {}
                    for index, column in enumerate(value):
                        if columns[index][1] == 2 and column is not None and isinstance(column, bytes):
                            try:
                                date_from_byte = self._bytes_to_date(column)
                                column = str(date_from_byte)
                            except:
                                column = '0x{0}'.format(binascii.hexlify(column).decode().upper())
                        column_dict[columns[index][0]] = column
                    results.append(column_dict)
                summary['num_rows'] = len(results)
            else:
                results = [{"Status": "Successfully executed SQL statement"}]
                summary['num_rows'] = 0
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Unable to retrieve results from query, Error: {}".format(error_message),
                None
            ))
        return RetVal(phantom.APP_SUCCESS, results)

    def _check_for_valid_schema(self, action_result, schema):
        format_vars = (schema, )
        query = "SELECT * FROM sys.schemas WHERE name = %s;"
        try:
            self._cursor.execute(query, format_vars)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error searching for schema, Error: {}".format(error_message)
            )

        results = self._cursor.fetchall()
        if len(results) == 0:
            return action_result.set_status(phantom.APP_ERROR, "The specified schema could not be found")

        return phantom.APP_SUCCESS

    def _check_for_valid_table(self, action_result, table, check_single=False):
        # check_single will ensure there is only one table with this name
        # If more are found, it will throw an error saying a schema is required
        format_vars = (table,)
        query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = %s;"
        try:
            self._cursor.execute(query, format_vars)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error searching for table, Error: {}".format(error_message)
            )

        results = self._cursor.fetchall()
        if len(results) == 0:
            return action_result.set_status(phantom.APP_ERROR, "The specified table could not be found")
        elif check_single and len(results) > 1:  # There is more than 1 table
            return action_result.set_status(
                phantom.APP_ERROR, "More than 1 table has that name. Please specify a table schema to distinguish the table"
            )

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query = "SELECT @@version;"
        try:
            self._cursor.execute(query)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Test Connectivity Failed, Error: {}".format(error_message)
            )

        for row in self._cursor:
            self.save_progress("{}".format(row[0]))

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_tables(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        table_schema = param.get('table_schema')
        dbname = param['database']

        query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = %s AND TABLE_CATALOG = %s"

        if table_schema:
            if phantom.is_fail(self._check_for_valid_schema(action_result, table_schema)):
                return phantom.APP_ERROR
            format_vars = ('BASE TABLE', dbname, table_schema)
        else:
            format_vars = ('BASE TABLE', dbname)
        try:
            self._cursor.execute(query, format_vars)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error listing tables, Error: {}".format(error_message)
            )

        ret_val, results = self._get_query_results(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        for row in results:
            action_result.add_data(row)

        summary = action_result.update_summary({})
        summary['num_tables'] = len(results)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_columns(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        table_name = param.get('table_name')
        table_schema = param.get('table_schema')
        dbname = param['database']

        if phantom.is_fail(self._check_for_valid_table(action_result, table_name, not bool(table_schema))):
            return phantom.APP_ERROR

        query = "SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = %s AND TABLE_CATALOG = %s"

        if table_schema:
            if phantom.is_fail(self._check_for_valid_schema(action_result, table_schema)):
                return phantom.APP_ERROR
            query += " AND TABLE_SCHEMA = %s"
            format_vars = (table_name, dbname, table_schema)
        else:
            format_vars = (table_name, dbname)

        try:
            self._cursor.execute(query, format_vars)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error listing columns, Error: {}".format(error_message)
            )

        ret_val, results = self._get_query_results(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        for row in results:
            action_result.add_data(row)

        if len(results) == 0:
            return action_result.set_status(phantom.APP_ERROR, "Table does not exist in specified schema")
        summary = action_result.update_summary({})
        summary['num_columns'] = len(results)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_format_vars(self, param):
        format_vars = param.get('format_vars', [])
        if format_vars:
            format_vars = tuple(next(csv.reader([format_vars], quotechar='"', skipinitialspace=True, escapechar='\\')))
        return format_vars

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query = param['query']
        format_vars = self._get_format_vars(param)
        try:
            self._cursor.execute(query, format_vars)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error running query, Error: {}".format(error_message)
            )

        ret_val, results = self._get_query_results(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        if not param.get('no_commit', False):
            try:
                self._connection.commit()
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(
                    phantom.APP_ERROR, "unable to commit changes, Error: {}".format(error_message)
                )

        for row in results:
            action_result.add_data(
                {key: str(value) for key, value in row.items()}
            )

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # To make this app work in a targeted mode where you can specify the
        # host with each action, the code to connect to the database was moved
        # from initialize to here.
        if phantom.is_fail(self._connect_sql(param)):
            action_result = self.add_action_result(ActionResult(dict(param)))
            action_result.set_status(phantom.APP_ERROR, "Unable to connect to host: {0}".format(param['host']))
            return phantom.APP_ERROR

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        if action_id == 'list_tables':
            ret_val = self._handle_list_tables(param)

        if action_id == 'list_columns':
            ret_val = self._handle_list_columns(param)

        if action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        return ret_val

    def _connect_sql(self, param):
        self._state = self.load_state()

        config = self.get_config()
        param = self.get_current_param()
        username = config['username']
        password = config['password']
        host = config['host']
        database = param.get('database', config['database'])
        param['database'] = database
        param['host'] = host
        try:
            self._connection = pymssql.connect(
                server=host, user=username, password=password, database=database, port=MSAZURESQL_PORT
            )
            self._cursor = self._connection.cursor()
        except Exception as e:
            self._dump_error_log(e)
            return self._initialize_error("Error authenticating with database", e)

        # check for the connection to the host
        if self._cursor is None:
            return self._initialize_error("Error connecting to host: {}".format(host))

        self.save_progress("Database connection established")
        return phantom.APP_SUCCESS

    def initialize(self):
        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=verify, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: {}".format(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MicrosoftAzureSqlConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)

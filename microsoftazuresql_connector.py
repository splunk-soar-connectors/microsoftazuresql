# File: microsoftazuresql_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# from microsoftazuresql_consts import *
import json
import binascii
import requests
from bs4 import BeautifulSoup


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

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200 or response.status_code == 202:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, u"Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = u'\n'.join(split_lines)
        except:
            error_text = u"Cannot parse error details"

        message = u"Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', u'{{').replace(u'}', u'}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = u"Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', u'{{').replace(u'}', u'}}'))

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

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = u"Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_query_results(self, action_result):

        try:
            results = []
            columns = self._cursor.description

            if columns:
                for value in self._cursor.fetchall():

                    column_dict = {}

                    for index, column in enumerate(value):

                        if columns[index][1] == 2 and column is not None:
                            column = '0x{0}'.format(binascii.hexlify(column).decode().upper())

                        column_dict[columns[index][0]] = column

                    results.append(column_dict)
            else:
                results = []
        except Exception as e:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Unable to retrieve results from query",
                e
            ))
        return RetVal(phantom.APP_SUCCESS, results)

    def _check_for_valid_schema(self, action_result, schema):
        query = "SELECT * FROM sys.schemas WHERE name = " + "'" + schema + "';"
        try:
            self._cursor.execute(query)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error searching for schema", e
            )

        results = self._cursor.fetchall()
        if len(results) == 0:
            return action_result.set_status(phantom.APP_ERROR, "The specified schema could not be found")

        return phantom.APP_SUCCESS

    def _check_for_valid_table(self, action_result, table, check_single=False):
        # check_single will ensure there is only one table with this name
        # If more are found, it will throw an error saying a schema is required
        query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = " + "'" + table + "';"
        try:
            self._cursor.execute(query)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error searching for table", e
            )

        results = self._cursor.fetchall()
        if len(results) == 0:
            return action_result.set_status(phantom.APP_ERROR, "The specified table could not be found")
        elif check_single and len(results) > 1:  # There is more than 1 table
            return action_result.set_status(
                phantom.APP_ERROR, "More than 1 table has that name. Please specify a table schema to distinguish the table"
            )

        return phantom.APP_SUCCESS

    def _check_server(self, connection_string):
        # Checking if the Server field of the Custom Connection String is filled out
        values = connection_string.split(';')
        length = 0
        for value in values:
            if value.startswith('Server'):
                length = len(value.replace('Server=', ''))
                break
        return length

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query = "SELECT @@version;"
        try:
            self._cursor.execute(query)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Test Connectivity Failed", e
            )

        for row in self._cursor:
            self.save_progress("{}".format(row[0]))

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_tables(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        table_schema = param.get('table_schema')

        query = "SELECT TABLE_NAME, TABLE_SCHEMA, TABLE_CATALOG FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"

        if table_schema:
            if phantom.is_fail(self._check_for_valid_schema(action_result, table_schema)):
                return phantom.APP_ERROR
            query += " AND TABLE_SCHEMA = " + "'" + table_schema + "'"

        try:
            self._cursor.execute(query)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error listing tables", e
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

        if phantom.is_fail(self._check_for_valid_table(action_result, table_name, not bool(table_schema))):
            return phantom.APP_ERROR

        query = "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = " + "'" + table_name + "'"

        if table_schema:
            if phantom.is_fail(self._check_for_valid_schema(action_result, table_schema)):
                return phantom.APP_ERROR
            query += " AND TABLE_SCHEMA = " + "'" + table_schema + "'"

        try:
            self._cursor.execute(query)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error listing columns", e
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

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query = param['query']

        try:
            self._cursor.execute(query)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error running query", e
            )

        ret_val, results = self._get_query_results(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        if not param.get('no_commit', False):
            try:
                self._connection.commit()
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "unable to commit changes", e
                )

        for row in results:
            action_result.add_data(
                {key: unicode(value) for key, value in row.items()}
            )

        summary = action_result.update_summary({})
        summary['num_rows'] = len(results)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully ran query")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

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

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        config = self.get_config()
        # get the asset config
        if config.get('connection_string'):
            connection_string = config['connection_string']
            if self._check_server(connection_string) == 0:
                return self.set_status(phantom.APP_ERROR, "Test Connectivity Failed due to missing Server/IP Address field")
        else:
            config = self.get_config()
            username = config.get('username')
            password = config.get('password')
            try:
                host = config['host']
            except Exception:
                return self.set_status(phantom.APP_ERROR, "Test Connectivity Failed due to missing Server/IP Address field")
            database = config.get('database')
            if config.get('driver'):
                driver = config['driver']
                driver = '{' + driver + '}'
            if config.get('trust_server'):
                trust_server = 'yes'
            else:
                trust_server = 'no'
            connection_string = """Driver={driver};Server={host},1433;Database={database};Uid={uid};Pwd={pwd};Encrypt=no;
                            TrustServerCertificate={trust_server};Trusted_Connection=no;
                            Connection Timeout=30;""".format(driver=driver, host=host, database=database, uid=username, pwd=password, trust_server=trust_server)

        self.debug_print(connection_string)
        # Check to see if user has installed the pyodbc driver
        try:
            import pyodbc
        except ImportError:
            return self.set_status(phantom.APP_ERROR, "Test Connectivity Failed due to missing pyodbc driver. Please install with the instructions in the app's documentation")

        try:
            self._connection = pyodbc.connect(
                connection_string
            )
            self._cursor = self._connection.cursor()
        except Exception as e:
            return self._initialize_error("Error authenticating with database", e)
        self.save_progress("Database connection established")
        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MicrosoftAzureSqlConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

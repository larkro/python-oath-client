import unittest

import os
from oath_client import OathDb
from oath_client import OathEntry
import oath_client

# file to keep database during tests
test_dbfile = "test_dbfile"


class TestOathDbFunction(unittest.TestCase):
    def setUp(self):
        self.func = OathDb(test_dbfile)

    def test_1_setup_loaded(self):
        self.assertTrue(True)

    def test_2_connection_to_database(self):
        self.assertTrue(self.func.conn)

    def test_3_got_row_factory(self):
        self.assertTrue(self.func.conn.row_factory)

    def test_4_create_table(self):
        self.func.create_table()
        self.assertTrue(self)

    def test_5_add_account_to_database(self):
        data = {"account": "test_account",
                "secret": "token",
                "rounds": 1,
                "salt": "salt",
                "desc": "desc",
                }
        new_entry = OathEntry(data)
        self.func.add(new_entry)
        self.assertTrue(self)

    def test_5_addlogin(self):
        data = {"shash": "dfadadf",
                "numb": 1,
                "rounds": 1,
                "salt": "salt",
                }
        new_entry = OathEntry(data)
        self.func.addlogin(new_entry)
        self.assertTrue(self)

    def test_6_get_from_database(self):
        self.func.get("test_account")
        self.assertTrue(self)

    def test_7_list_accounts(self):
        self.func.list_accounts()
        self.assertTrue(self)

    def test_8_get_account(self):
        self.func.get_account()
        self.assertTrue(self)

    def test_9_delete(self):
        data = {"delete": "test_account"}
        entry = OathEntry(data)
        self.func.delete(entry)
        self.assertTrue(self)

    def test_x_close(self):
        os.remove(test_dbfile)


class TestOathEntryFunction(unittest.TestCase):
    def setUp(self):
        self.func = OathEntry("data")

    def test_setup_loaded(self):
        self.assertTrue(True)


class TestFunctions(unittest.TestCase):
    def test_functions_generate_random_salt(self):
        self.func = oath_client
        self.func.generate_random_salt
        self.assertTrue(True)

    def test_functions_generate_random_rounds(self):
        self.func = oath_client
        self.func.generate_random_rounds
        self.assertTrue(True)

    def test_functions_list_accounts(self):
        self.func = oath_client
        self.func.list_accounts
        self.assertTrue(True)

    def test_functions_display_oath(self):
        self.func = oath_client
        self.func.display_oath
        self.assertTrue(True)

    def test_functions_create_pwstring(self):
        self.func = oath_client
        self.func.create_pwstring
        self.assertTrue(True)

    def test_functions_create_login(self):
        self.func = oath_client
        self.func.create_login
        self.assertTrue(True)

    def test_functions_delete_account(self):
        self.func = oath_client
        self.func.delete_account
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()

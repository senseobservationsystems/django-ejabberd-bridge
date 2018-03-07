# -*- coding: utf-8 -*-
# Copyright (C) 2013  Fabio Falcinelli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from io import StringIO
import io
import struct
import datetime
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.test import TestCase
from mock import patch
from ejabberd_bridge.management.commands import ejabberd_auth
from rest_framework import exceptions
from knox.models import AuthToken

__author__ = 'taufik'


class AuthBridgeTestCase(TestCase):
    fixtures = ["auth"]

    def setUp(self):
        super(AuthBridgeTestCase, self).setUp()
        self.cmd = ejabberd_auth.Command()
        self.srv = "localhost"
        self.user_model = get_user_model()

    def tearDown(self):
        pass

    def _check_cmd_parsing(self, params):
        data = struct.pack(">H", len(params)) + params.encode("utf-8")
        with patch("sys.stdin", StringIO(data.decode("utf-8"))):
            result = self.cmd.from_ejabberd()
        self.assertSequenceEqual(result, params.split(":"))

    def test_from_jabber_auth(self):
        """
        Tests the parsing of the auth command
        """
        params = "auth:User:Server:token"
        self._check_cmd_parsing(params)

    def test_from_jabber_isuser(self):
        """
        Tests the parsing of the isuser command
        """
        params = "isuser:User:Server"
        self._check_cmd_parsing(params)

    def test_from_jabber_setpass(self):
        """
        Tests the parsing of the setpass command
        """
        params = "setpass:User:Server:token"
        self._check_cmd_parsing(params)

    def test_to_jabber_true(self):
        """
        Tests conversion from python True value to bytes suitable for eJabberd
        """
        with patch("sys.stdout", new_callable=StringIO) as stdout_mocked:
            self.cmd.to_ejabberd(True)
        self.assertEqual(stdout_mocked.getvalue(), '\x00\x02\x00\x01')

    def test_to_jabber_false(self):
        """
        Tests conversion from python False value to bytes suitable for eJabberd
        """
        with patch("sys.stdout", new_callable=StringIO) as stdout_mocked:
            self.cmd.to_ejabberd(False)
        self.assertEqual(stdout_mocked.getvalue(), '\x00\x02\x00\x00')

    def test_isuser_ok(self):
        """
        Tests isuser command with a existent and valid user
        """
        user_id = 1
        self.assertTrue(self.cmd.isuser(user_id=user_id, server=self.srv))

    def test_isuser_does_not_exists(self):
        """
        Tests isuser command with an user which does not exist
        """
        user_id = 30
        self.assertFalse(self.cmd.isuser(user_id=user_id, server=self.srv))

    def test_auth_ok(self):
        """
        Tests auth command with a right user and token pair
        """
        user_id = 3
        user = self.user_model.objects.get(id=user_id)
        token = AuthToken.objects.create(user)
        self.assertTrue(self.cmd.auth(user_id=user_id, server=self.srv, token=token))

    def test_auth_wrong_token(self):
        """
        Tests auth command with a right user but wrong token
        """
        user_id = 1
        token = "WRONG"
        with self.assertRaises(exceptions.AuthenticationFailed) as cm:
            self.cmd.auth(user_id=user_id, server=self.srv, token=token)
        self.assertEqual(cm.exception.detail.decode("utf-8"), "Invalid token.")

    def test_auth_token_expired(self):
        """
        Tests auth command with a right user but token expired
        """
        user_id = 1
        user = self.user_model.objects.get(id=user_id)
        token = AuthToken.objects.create(user=user, expires=datetime.timedelta(seconds=0))
        with self.assertRaises(exceptions.AuthenticationFailed) as cm:
            self.cmd.auth(user_id=user_id, server=self.srv, token=token)
        self.assertEqual(cm.exception.detail.decode("utf-8"), "Invalid token.")

    def test_auth_does_not_exist(self):
        """
        Tests auth command with a non existent user
        """
        user_id = "user_that_does_not_exists"
        token = "token"
        with self.assertRaises(exceptions.AuthenticationFailed) as cm:
            self.cmd.auth(user_id=user_id, server=self.srv, token=token)
        self.assertEqual(cm.exception.detail.decode("utf-8"), "Invalid token.")

    def test_auth_not_active(self):
        """
        Tests auth command with a right user and token pair but user is not active
        """
        user_id = 2
        user = self.user_model.objects.get(id=user_id)
        token = default_token_generator.make_token(user)
        with self.assertRaises(exceptions.AuthenticationFailed) as cm:
            self.cmd.auth(user_id=user_id, server=self.srv, token=token)
        self.assertEqual(cm.exception.detail.decode("utf-8"), "Invalid token.")

    def _execute_cmd_handle(self, params):
        data = struct.pack(">H", len(params)) + params.encode("utf-8")
        with patch("sys.stdin", StringIO(data.decode("utf-8"))), patch("sys.stdout",
                                                                       new_callable=StringIO) as stdout_mocked:
            self.cmd.handle(params, run_forever=False)
        return stdout_mocked.getvalue()

    def test_handle_auth_ok(self):
        """
        Tests successful auth command thorugh the handle method
        """
        user_id = 3
        user = self.user_model.objects.get(id=user_id)
        token = AuthToken.objects.create(user)
        params = "auth:{}:localhost:{}".format(user_id, token)
        self.assertEqual('\x00\x02\x00\x01', self._execute_cmd_handle(params))

    def test_handle_auth_nok(self):
        """
        Tests failing auth command thorugh the handle method
        """
        params = "auth:User:Server:token"
        self.assertEqual('\x00\x02\x00\x00', self._execute_cmd_handle(params))
    
    def test_handle_auth_token_expired(self):
        """
        Tests failing auth command because token was expired thorugh the handle method
        """
        user_id = 3
        user = self.user_model.objects.get(id=user_id)
        token = AuthToken.objects.create(user=user, expires=datetime.timedelta(seconds=0))
        params = "auth:{}:localhost:{}".format(user_id, token)
        self.assertEqual('\x00\x02\x00\x00', self._execute_cmd_handle(params))

    def test_handle_isuser_ok(self):
        """
        Tests successful isuser command thorugh the handle method
        """
        params = "isuser:3:localhost"
        self.assertEqual('\x00\x02\x00\x01', self._execute_cmd_handle(params))

    def test_handle_isuser_nok(self):
        """
        Tests failing isuser command thorugh the handle method
        """
        params = "isuser:User:Server"
        self.assertEqual('\x00\x02\x00\x00', self._execute_cmd_handle(params))

    def test_handle_invalid_data(self):
        """
        Tests failing with invalid bytes argument
        """
        params = "foo bar"
        data = struct.pack(">H", len(params) + 10) + params.encode("utf-8")
        with patch("sys.stdin", io.BytesIO(data)), patch("sys.stdout", new_callable=StringIO) as stdout_mocked:
            self.cmd.handle(params, run_forever=False)
        self.assertEqual('\x00\x02\x00\x00', stdout_mocked.getvalue())
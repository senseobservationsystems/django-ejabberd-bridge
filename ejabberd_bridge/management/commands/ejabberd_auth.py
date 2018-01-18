#!/usr/bin/python
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
import logging
import struct
import sys
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

__author__ = "taufik"


class Command(BaseCommand):

    logger = logging.getLogger(__name__)
    user_model = get_user_model()

    def from_ejabberd(self, encoding="utf-8"):
        """
        Reads data from stdin as passed by eJabberd
        """
        input_length = sys.stdin.read(2).encode(encoding)
        (size,) = struct.unpack(">h", input_length)
        return sys.stdin.read(size).split(":")

    def to_ejabberd(self, answer=False):
        """
        Converts the response into eJabberd format
        """
        b = struct.pack('>hh',
                        2,
                        1 if answer else 0)
        self.logger.debug("To jabber: %s" % b)
        sys.stdout.write(b.decode("utf-8"))
        sys.stdout.flush()

    def auth(self, user_id=None, server="localhost", password=None):
        self.logger.debug("Authenticating %s on server %s" % (username, server))

        try:
            user_obj = self.user_model.objects.get(id=user_id)            
            user = authenticate(username=user_obj.username, password=password)

            if user :
                return True
            else:
                return False
        except User.DoesNotExist:
            return False

    def isuser(self, user_id=None, server="localhost"):
        """
        Checks if the user exists and is active
        """
        self.logger.debug("Validating %s on server %s" % (user_id, server))

        try:
            user = self.user_model.objects.get(id=user_id)
            return True
        except User.DoesNotExist:
            return False

    def handle(self, *args, **options):
        """
        Gathers parameters from eJabberd and executes authentication
        against django backend
        """
        logging.basicConfig(
           level="DEBUG",
           format='%(asctime)s %(levelname)s %(message)s',
           filename=settings.DJANGO_EJABBERD_BRIDGE_LOG,
           filemode='a')

        self.logger.debug("Starting serving authentication requests for eJabberd")
        success = False
        try:
            while True:
                data = self.from_ejabberd()
                self.logger.debug("Command is %s" % data[0])
                if data[0] == "auth":
                    success = self.auth(data[1], data[2], data[3])
                elif data[0] == "isuser":
                    success = self.isuser(data[1], data[2])
                elif data[0] == "setpass":
                    success = False
                self.to_ejabberd(success)
                if not options.get("run_forever", True):
                    break
        except Exception as e:
            self.logger.error("An error has occurred during eJabberd external authentication: %s" % e)
            self.to_ejabberd(success)
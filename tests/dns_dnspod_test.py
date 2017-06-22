# -*- coding: utf-8 -*-
"""Tests for certbot_dns_dnspod.dns_dnspod."""

import os
import random

import mock

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util


API_TOKEN = "APITOKEN-{0}".format(random.random())
EMAIL = "{0}@{0}.com".format(random.random())


class AuthenticatorTest(
        test_util.TempDirTestCase,
        dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        from certbot_dns_dnspod.dns_dnspod import Authenticator

        super(AuthenticatorTest, self).setUp()
        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {"dnspod_email": EMAIL, "dnspod_api_token": API_TOKEN},
            path
        )
        self.config = mock.MagicMock(
            dnspod_credentials=path,
            dnspod_propagation_seconds=0  # don"t wait during tests
        )
        self.auth = Authenticator(self.config, "dnspod")
        self.mock_client = mock.MagicMock()
        # _get_cloudflare_client | pylint: disable=protected-access
        self.auth.dnspod = self.mock_client

    def test_perform(self):
        self.auth.perform([self.achall])
        self.mock_client.set_credentials.assert_called_once_with(
            EMAIL, API_TOKEN
        )
        self.mock_client.add_txt_record.assert_called_once_with(
            "_acme-challenge." + DOMAIN, mock.ANY
        )

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])
        self.mock_client.remove_txt_record.assert_called_once_with(
            "_acme-challenge." + DOMAIN, mock.ANY
        )

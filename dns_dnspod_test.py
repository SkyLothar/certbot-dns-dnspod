# -*- coding: utf-8 -*-
"""Tests for certbot_dns_dnspod.dns_dnspod."""

import os
import random
import unittest

import mock
import responses
import requests

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util


if requests.compat.is_py2:
    from urlparse import parse_qsl
else:
    from urllib.parse import parse_qsl

API_TOKEN = "APITOKEN-{0}".format(random.random())
EMAIL = "{0}@{0}.com".format(random.random())


def parse_data(encoded_data):
    return dict(parse_qsl(encoded_data))


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


class DnspodClientTest(unittest.TestCase):
    domain = DOMAIN
    sub_domain = "subdomain-{0}".format(random.random())
    record_id = "rid-{0}".format(random.random())
    record_name = ".".join([sub_domain, domain])
    record_value = "record-value-{0}".format(random.random())
    ttl = random.randint(100, 600)
    error = "error-{0}".format(random.random())
    common_params = {
        "error_on_empty": "no",
        "format": "json",
        "lang": "en",
        "login_token": API_TOKEN
    }

    def setUp(self):
        from certbot_dns_dnspod.client import DnspodClient
        self.dnspod = DnspodClient(EMAIL, API_TOKEN)
        self.dnspod.ttl = self.ttl

    def get_params(self, extra):
        expected = self.common_params.copy()
        expected.update(extra)
        return expected

    @responses.activate
    def test_add_txt_record(self):
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.Create",
            json={"status": {"code": "1"}}
        )
        self.dnspod.add_txt_record(self.record_name, self.record_value)
        expected = self.get_params({
            "record_type": "TXT",
            "record_line": "默认",
            "ttl": str(self.ttl),
            "domain": DOMAIN,
            "sub_domain": self.sub_domain,
            "value": self.record_value
        })
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(parse_data(responses.calls[0].request.body), expected)

    @responses.activate
    def test_add_txt_record_error(self):
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.Create",
            json={"status": {"code": "-1", "message": self.error}}
        )

        with self.assertRaisesRegexp(errors.PluginError, self.error):
            self.dnspod.add_txt_record(self.record_name, self.record_value)

    def test_add_txt_sub_domain_not_found(self):
        with self.assertRaisesRegexp(
            errors.PluginError,
            "Unable to determine sub_domain for wrong-domain."
        ):
            self.dnspod.add_txt_record("wrong-domain", self.record_value)

    @responses.activate
    def test_remove_txt_record(self):
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.List",
            json={
                "status": {"code": "1"},
                "records": [
                    {"id": "err-0", "type": "A", "value": self.record_value},
                    {"id": "err-1", "type": "TXT", "value": "some-value"},
                    {
                        "id": self.record_id,
                        "type": "TXT",
                        "value": self.record_value
                    }
                ]
            }
        )
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.Remove",
            json={"status": {"code": "1"}}
        )
        self.dnspod.remove_txt_record(self.record_name, self.record_value)
        self.assertEqual(len(responses.calls), 2)

        expected_list = self.get_params({
            "domain": self.domain,
            "sub_domain": self.sub_domain
        })
        self.assertEqual(
            parse_data(responses.calls[0].request.body),
            expected_list
        )

        expected_remove = self.get_params({
            "domain": self.domain,
            "record_id": self.record_id
        })
        self.assertEqual(
            parse_data(responses.calls[1].request.body),
            expected_remove
        )

    @responses.activate
    def test_remove_txt_record_error_during_record_id_lookup(self):
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.List",
            json={"status": {"code": "-1", "message": self.error}}
        )
        self.dnspod.remove_txt_record(self.record_name, self.record_value)

    @responses.activate
    def test_move_txt_record_error_during_delete(self):
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.List",
            json={
                "status": {"code": "1"},
                "records": [{
                    "id": self.record_id,
                    "type": "TXT",
                    "value": self.record_value
                }]
            }
        )
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.Remove",
            json={"status": {"code": "-1", "message": self.error}}
        )
        self.dnspod.remove_txt_record(self.record_name, self.record_value)
        self.assertEqual(len(responses.calls), 2)

        expected_list = self.get_params({
            "domain": self.domain,
            "sub_domain": self.sub_domain
        })
        self.assertEqual(
            parse_data(responses.calls[0].request.body),
            expected_list
        )

        expected_remove = self.get_params({
            "domain": self.domain,
            "record_id": self.record_id
        })
        self.assertEqual(
            parse_data(responses.calls[1].request.body),
            expected_remove
        )

    @responses.activate
    def test_remove_txt_record_no_record(self):
        responses.add(
            responses.POST, "https://dnsapi.cn/Record.List",
            json={
                "status": {"code": "1"},
                "records": [
                    {"id": "err-0", "type": "A", "value": self.record_value}
                ]
            }
        )
        self.dnspod.remove_txt_record(self.record_name, self.record_value)

        self.assertEqual(len(responses.calls), 1)
        expected_list = self.get_params({
            "domain": self.domain,
            "sub_domain": self.sub_domain
        })
        self.assertEqual(
            parse_data(responses.calls[0].request.body),
            expected_list
        )


if __name__ == "__main__":
    unittest.main()

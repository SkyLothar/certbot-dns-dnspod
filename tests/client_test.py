# -*- coding: utf-8 -*-
"""Tests for certbot_dns_dnspod.client"""

import responses
import pytest
import requests

from certbot import errors
from certbot.plugins.dns_test_common import DOMAIN
from certbot_dns_dnspod.client import DnspodClient


if requests.compat.is_py2:
    from urlparse import parse_qsl  # pylint: disable=E0611,E0401
else:
    from urllib.parse import parse_qsl  # pylint: disable=E0611,E0401

API_TOKEN = "APITOKEN"
EMAIL = "example@example.com"
SUB_DOMAIN = "subdomain"
RECORD_ID = "rid"
RECORD_NAME = ".".join([SUB_DOMAIN, DOMAIN])
RECORD_VALUE = "record-value"
TTL = 42
ERROR_MSG = "dnspod-error-message"
ERROR = {"status": {"code": "-1", "message": ERROR_MSG}}


@pytest.fixture
def dnspod():
    dnspod = DnspodClient(EMAIL, API_TOKEN)
    dnspod.ttl = TTL
    return dnspod


def parse_data(encoded_data):
    return dict(parse_qsl(encoded_data))


def get_params(extra):
    common_params = {
        "error_on_empty": "no",
        "format": "json",
        "lang": "en",
        "login_token": API_TOKEN
    }
    common_params.update(extra)
    return common_params


@responses.activate
def test_add_txt_record(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.Create",
        json={"status": {"code": "1"}}
    )
    dnspod.add_txt_record(RECORD_NAME, RECORD_VALUE)
    expected = get_params({
        "record_type": "TXT",
        "record_line": "默认",
        "ttl": str(TTL),
        "domain": DOMAIN,
        "sub_domain": SUB_DOMAIN,
        "value": RECORD_VALUE
    })
    assert len(responses.calls) == 1
    assert parse_data(responses.calls[0].request.body) == expected


@responses.activate
def test_add_txt_record_error(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.Create", json=ERROR
    )

    with pytest.raises(errors.PluginError, message=ERROR_MSG):
        dnspod.add_txt_record(RECORD_NAME, RECORD_VALUE)


def test_add_txt_sub_domain_not_found(dnspod):
    with pytest.raises(
        errors.PluginError,
        mesage="Unable to determine sub_domain for wrong-domain."
    ):
        dnspod.add_txt_record("wrong-domain", RECORD_VALUE)


@responses.activate
def test_remove_txt_record(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.List",
        json={
            "status": {"code": "1"},
            "records": [
                {"id": "err-0", "type": "A", "value": RECORD_VALUE},
                {"id": "err-1", "type": "TXT", "value": "some-value"},
                {"id": RECORD_ID, "type": "TXT", "value": RECORD_VALUE}
            ]
        }
    )
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.Remove",
        json={"status": {"code": "1"}}
    )
    dnspod.remove_txt_record(RECORD_NAME, RECORD_VALUE)
    assert len(responses.calls) == 2

    expected_list = get_params({"domain": DOMAIN, "sub_domain": SUB_DOMAIN})
    assert parse_data(responses.calls[0].request.body) == expected_list

    expected_remove = get_params({"domain": DOMAIN, "record_id": RECORD_ID})
    assert parse_data(responses.calls[1].request.body), expected_remove


@responses.activate
def test_remove_txt_record_error_during_record_id_lookup(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.List",
        json=ERROR
    )
    dnspod.remove_txt_record(RECORD_NAME, RECORD_VALUE)


@responses.activate
def test_move_txt_record_error_during_delete(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.List",
        json={
            "status": {"code": "1"},
            "records": [
                {"id": RECORD_ID, "type": "TXT", "value": RECORD_VALUE}
            ]
        }
    )
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.Remove", json=ERROR
    )
    dnspod.remove_txt_record(RECORD_NAME, RECORD_VALUE)
    assert len(responses.calls) == 2

    expected_list = get_params({"domain": DOMAIN, "sub_domain": SUB_DOMAIN})
    assert parse_data(responses.calls[0].request.body) == expected_list

    expected_remove = get_params({"domain": DOMAIN, "record_id": RECORD_ID})
    assert parse_data(responses.calls[1].request.body) == expected_remove


@responses.activate
def test_remove_txt_record_no_record(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.List",
        json={
            "status": {"code": "1"},
            "records": [
                {"id": "err-0", "type": "A", "value": RECORD_VALUE}
            ]
        }
    )
    dnspod.remove_txt_record(RECORD_NAME, RECORD_VALUE)

    assert len(responses.calls) == 1
    expected_list = get_params({"domain": DOMAIN, "sub_domain": SUB_DOMAIN})
    assert parse_data(responses.calls[0].request.body) == expected_list


@responses.activate
def test_move_txt_record_http_error(dnspod):
    responses.add(
        responses.POST, "https://dnsapi.cn/Record.List", status=500
    )
    dnspod.remove_txt_record(DOMAIN, RECORD_VALUE)

    assert len(responses.calls) == 1

    expected_list = get_params({
        "domain": DOMAIN,
        "sub_domain": "@"
    })
    assert parse_data(responses.calls[0].request.body) == expected_list

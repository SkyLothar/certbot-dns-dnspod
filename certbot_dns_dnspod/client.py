# -*- coding: utf8 -*-

import logging

import requests

from certbot import errors
from certbot.plugins import dns_common

__version__ = "0.0.1"


logger = logging.getLogger(__name__)

class DnspodClient(object):
    """
    Encapsulates all communication with the DNSPOD API.
    """

    session = requests.session()
    ttl = 600
    endpoint = "https://dnsapi.cn"

    def __init__(self, email=None, token=None):
        self.common_params = {}
        self.set_credentials(email, token)

    def set_credentials(self, email, token):
        """Setup credentials for DNSPOD API

        :param str email: You need to provide a valid email address to use
            DNSPOD api. More details can be found in
            (https://www.dnspod.cn/docs/info.html).
        :param str token: The DNSPOD API Token, you can find it in
            [https://www.dnspod.cn/console/user/security].
        """

        if email is not None:
            self.session.headers.update({
                "User-Agent":
                "CertbotDnspod/{0}({1})".format(__version__, email)
            })
        if token is not None:
            self.common_params = dict(
                login_token=token, format="json",
                lang="en", error_on_empty="no",
            )

    def add_txt_record(self, record, value):
        """
        Add a TXT record using the supplied information.

        :param str record: The record name
            (typically beginning with "_acme-challenge.").
        :param str value: The record content
            (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs when
            communicating with the DNSPOD API
        """

        sub_domain, domain = self.get_base_domain(record)
        self._call(
            "Record.Create",
            {
                "domain": domain,
                "sub_domain": sub_domain,
                "record_type": u"TXT",
                "record_line": u"默认",
                "value": value,
                "ttl": self.ttl
            }
        )

    def remove_txt_record(self, record, value):
        """
        Delete a TXT record using the supplied information.
        Note that both the record"s name and value are used to ensure that
            similar records created concurrently
            (e.g., due to concurrent invocations of this plugin)
            are not deleted.
        Failures are logged, but not raised.

        :param str record: The record name
            (typically beginning with "_acme-challenge.").
        :param str value: The record content
            (typically the challenge validation).
        """

        try:
            ___, domain = self.get_base_domain(record)
            record_id = self._find_txt_record(record, value)
            if record_id is not None:
                self._call(
                    "Record.Remove",
                    {
                        "domain": domain,
                        "record_id": record_id
                    }
                )
        except errors.PluginError as e:
            logger.debug(
                u"Encountered error during deletion: [%s]", e
            )
            return None

    def _find_txt_record(self, record_name, value):
        """
        Find the record_id for a TXT record with the given name and content.

        :param str record_name: The record name
            (typically beginning with "_acme-challenge.").
        :param str value: The record content
            (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: int
        """

        sub_domain, domain = self.get_base_domain(record_name)
        data = self._call(
            "Record.List",
            {
                "domain": domain,
                "sub_domain": sub_domain
            }
        )
        for record in data["records"]:
            if record["type"] != u"TXT":
                continue
            if record["value"] != value:
                continue
            return record["id"]
        logger.error(u"TXT record of %s not found", record)

    def _find_all_domains(self):
        """
        Extrat all domain from DNSPOD
        :returns: all domain, if found.
        :rtype: []
        """
        domains = []
        data = self._call(
            "Domain.List",
            {
            }
        )
        
        for domain in data["domains"]:
            if domain["status"] != u"enable":
                continue
            name = domain["name"]
            domains.append(name)
        return domains

    def get_base_domain(self, record):
        """
        Extrat the "sub_domain" and "base_domain" for DNSPOD from given record

        :param str record: The record name
            (typically beginning with "_acme-challenge.").
        :returns: The sub_domain and domain, if found.
        :rtype: (str, str)
        :raises certbot.errors.PluginError: if no sub_domain is found.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(record)
    
        domains = self._find_all_domains()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', record, guess)
                sub_domain = record.rpartition("." + domain)[0]
                base_domain = domain
                logger.debug(u"%s => %s + %s", record, sub_domain, base_domain)
                return sub_domain, base_domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                         .format(record, domain_name_guesses))

    def _call(self, method, payload):
        """Attach common params and api token for dnspod api request

        :param str method: DNSPOD Api name
        :param dict payload: DNSPOD Api params
        :returns: The response data, if succeeded.
        :rtype: dict
        :raises certbot.errors.PluginError: if an error occurs
            when calling DNSPOD api
        """

        payload.update(self.common_params)
        resp = self.session.post(
            "{0}/{1}".format(self.endpoint, method), payload
        )
        error = None
        if resp.ok:
            data = resp.json()
            status = data["status"]
            if status["code"] != u"1":
                error = status["message"]
        else:
            error = u"http error status: {0}".format(resp.status_code)
        if error:
            logger.error(u"[DNSPOD] %s error: %s", method, error)
            raise errors.PluginError(
                u"Error communicating with the DNSPOD API: {0}".format(error)
            )
        return data

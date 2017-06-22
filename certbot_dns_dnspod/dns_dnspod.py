"""DNS Authenticator for DNSPOD."""

import zope.interface  # pylint: disable=W0403

from certbot import interfaces
from certbot.plugins import dns_common

from .client import DnspodClient


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNSPOD

    This Authenticator uses the DNSPOD API to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record "
        "(if you are using Cloudflare for DNS)."
    )

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        self.dnspod = DnspodClient()

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add)
        add("credentials", help="DNSPOD credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond "
            "to a dns-01 challenge using the DNSPOD API."
        )

    def _setup_credentials(self):
        credentials = self._configure_credentials(
            "credentials",
            "DNSPOD credentials INI file",
            {
                "email": "email address associated with DNSPOD account",
                "api-token": "API Token for DNSPOD account"
            }
        )
        self.dnspod.set_credentials(
            credentials.conf("email"),
            credentials.conf("api-token")
        )

    def _perform(self, domain, validation_domain_name, validation):
        self.dnspod.add_txt_record(validation_domain_name, validation)

    def _cleanup(self, domain, validation_domain_name, validation):
        self.dnspod.remove_txt_record(validation_domain_name, validation)

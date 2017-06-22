from codecs import open
from setuptools import find_packages, setup


__version__ = "0.1.0"
__author__ = "SkyLothar"
__email__ = "allothar@gmail.com"
__url__ = "http://github.com"

with open("README.rst", "r", "utf-8") as f:
    readme = f.read()

with open("requirements.txt", "r", "utf-8") as f:
    install_requirements = f.read()

with open("tests/requirements.txt", "r", "utf-8") as f:
    test_requirements = f.read()

setup(
    name="certbot-dns-dnspod",
    version=__version__,
    description="DNSPOD DNS Authenticator plugin for Certbot",
    long_description=readme,
    author=__author__,
    author_email=__email__,
    url=__url__,
    license="Apache License 2.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requirements,
    tests_require=test_requirements,
    entry_points={
        "certbot.plugins": [
            "dns-dnspod = certbot_dns_dnspod.dns_dnspod:Authenticator",
        ],
    },
    test_suite="certbot_dns_dnspod",
)

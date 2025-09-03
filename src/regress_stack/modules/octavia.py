# Copyright 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timedelta, timezone
import logging
import pathlib
import shutil

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from regress_stack.core import utils as core_utils
from regress_stack.modules import keystone, mysql, neutron, nova, ovn, rabbitmq
from regress_stack.modules import utils as module_utils

LOG = logging.getLogger(__name__)

DEPENDENCIES = {keystone, mysql, rabbitmq, ovn, nova, neutron}
PACKAGES = [
    "octavia-api",
    "octavia-housekeeping",
    "octavia-worker",
    "octavia-driver-agent",
    "python3-ovn-octavia-provider",
]
LOGS = ["/var/log/octavia/"]

CONF = "/etc/octavia/octavia.conf"
URL = f"http://{core_utils.my_ip()}:9876/"
SERVICE = "octavia"
SERVICE_TYPE = "load-balancer"
OCTAVIA_ROLES = (
    "load-balancer_admin",
    "load-balancer_observer",
    "load-balancer_global_observer",
    "load-balancer_member",
    "load-balancer_admin",
)
CERT_DIR = "/etc/octavia/certs"
AMPHORA_CA_CERT = str(pathlib.Path(CERT_DIR, "amphora_ca.cert.pem"))
AMPHORA_CA_KEY = str(pathlib.Path(CERT_DIR, "amphora_ca.key.pem"))
AMPHORA_CA_COMBINED = str(pathlib.Path(CERT_DIR, "amphora_ca.cert-and-key.pem"))
AMPHORA_CA_KEY_PASSPHRASE = "changeme"
SOCKET_DIR = "/var/run/octavia"


TEST_INCLUDE_REGEXES = [
    r"octavia_tempest_plugin.tests.scenario.*SIP.*",
    r"octavia_tempest_plugin.tests.scenario.*source_ip_port.*",
]

TEST_EXCLUDE_REGEXES = [
    # None of the following tests are supported by the ovn provider
    r"PROXY",
    r"HTTP",
    r"http",
    r"mixed",
    r"_RR_",
    r"_SI_",
    r"_LC_",
    r"L7",
    r"ListenerScenarioTest",
    # Tries to configure an interface called eth0 on spawned VM, but does not exist
    r"octavia_tempest_plugin.tests.scenario.v2.test_traffic_ops.*",
    r"octavia_tempest_plugin.tests.scenario.v2.test_ipv6_traffic_ops.*",
]


def create_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with open(AMPHORA_CA_KEY, "wb") as keyfile:
        keyfile.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    AMPHORA_CA_KEY_PASSPHRASE.encode("utf-8")
                ),
            )
        )

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "London"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Canonical Group Limited"),
            x509.NameAttribute(NameOID.COMMON_NAME, "regress-stack"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                crl_sign=True,
                key_cert_sign=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(AMPHORA_CA_CERT, "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(AMPHORA_CA_COMBINED, "wb") as combined:
        combined.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    AMPHORA_CA_KEY_PASSPHRASE.encode("utf-8")
                ),
            )
        )
        combined.write(cert.public_bytes(serialization.Encoding.PEM))


def setup():
    db_user, db_pass = mysql.ensure_service(SERVICE)
    rabbit_user, rabbit_pass = rabbitmq.ensure_service(SERVICE)
    username, password = keystone.ensure_service_account(SERVICE, SERVICE_TYPE, URL)
    for role in OCTAVIA_ROLES:
        keystone.ensure_role(role)
    socket_dir = pathlib.Path(SOCKET_DIR)
    socket_dir.mkdir(parents=True, exist_ok=True)
    shutil.chown(socket_dir, SERVICE, SERVICE)
    ca_dir = pathlib.Path(CERT_DIR)
    ca_dir.mkdir(parents=True, exist_ok=True)
    create_ca()
    module_utils.cfg_set(
        CONF,
        (
            "database",
            "connection",
            mysql.connection_string(SERVICE, db_user, db_pass),
        ),
        ("database", "max_pool_size", "1"),
        *module_utils.dict_to_cfg_set_args(
            "keystone_authtoken", keystone.authtoken_service(username, password)
        ),
        *module_utils.dict_to_cfg_set_args(
            "service_auth", keystone.account_dict(username, password)
        ),
        ("DEFAULT", "transport_url", rabbitmq.transport_url(rabbit_user, rabbit_pass)),
        ("oslo_messaging", "topic", "octavia_prov"),
        ("api_settings", "bind_host", "0.0.0.0"),
        (
            "api_settings",
            "enabled_provider_drivers",
            "ovn:Octavia OVN driver, amphora:Octavia Amphora driver",
        ),
        ("api_settings", "default_provider_driver", "ovn"),
        ("driver_agent", "enabled_provider_agents", "ovn"),
        *module_utils.dict_to_cfg_set_args(
            "ovn",
            {
                "ovn_nb_connection": ovn.OVNNB_CONNECTION,
                "ovn_sb_connection": ovn.OVNSB_CONNECTION,
            },
        ),
        *module_utils.dict_to_cfg_set_args(
            "certificates",
            {
                "cert_generator": "local_cert_generator",
                "ca_certificate": AMPHORA_CA_CERT,
                "ca_private_key": AMPHORA_CA_KEY,
                "ca_private_key_passphrase": AMPHORA_CA_KEY_PASSPHRASE,
            },
        ),
        ("controller_worker", "client_ca", AMPHORA_CA_CERT),
        ("haproxy_amphora", "client_cert", AMPHORA_CA_COMBINED),
        ("haproxy_amphora", "server_ca", AMPHORA_CA_CERT),
    )
    core_utils.sudo("octavia-db-manage", ["upgrade", "head"], user=SERVICE)
    core_utils.restart_service(
        "octavia-driver-agent", "octavia-worker", "octavia-api", "octavia-housekeeping"
    )


def configure_tempest(tempest_conf: pathlib.Path):
    """Configure tempest for Octavia."""
    module_utils.cfg_set(
        str(tempest_conf),
        *module_utils.dict_to_cfg_set_args(
            "load_balancer",
            {
                "member_role": "load-balancer_member",
                "admin_role": "load-balancer_admin",
                "observer_role": "load-balancer_observer",
                "global_observer_role": "load-balancer_global_observer",
                "RBAC_test_type": "keystone_default_roles",
                "enabled_provider_drivers": "ovn:Octavia OVN driver",
                "provider": "ovn",
            },
        ),
        *module_utils.dict_to_cfg_set_args(
            "loadbalancer-feature-enabled",
            {
                "health_monitor_enabled": "true",
                "l7_protocol_enabled": "false",
                "l4_protocol": "TCP",
                "session_persistence_enabled": "false",
                "pool_algorithms_enabled": "false",
                "quotas_enabled": "false",
                "not_implemented_is_error": "false",
            },
        ),
    )

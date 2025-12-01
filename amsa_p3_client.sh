#!/bin/bash
# Variables
LDAP_SERVER=$1
BASE="dc=amsa,dc=udl,dc=cat"
PATH_PKI="/etc/pki/tls"

# dews
curl -f http://$LDAP_SERVER:8080/cacerts.pem -o $PATH_PKI/cacerts.pem

# instalamos herramientas necessarias
dnf install -y openldap-clients sssd sssd-tools authselect oddjob-mkhomedir

# instalamos sssd
cat << EOL >> /etc/sssd/sssd.conf
[sssd]
services = nss, pam, sudo
config_file_version = 2
domains = default

[sudo]

[nss]

[pam]
offline_credentials_expiration = 60

[domain/default]
ldap_id_use_start_tls = True
cache_credentials = True
ldap_search_base = $BASE
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
access_provider = ldap
sudo_provider = ldap
ldap_uri = ldaps://$LDAP_SERVER
ldap_default_bind_dn = cn=osproxy,ou=system,$BASE
ldap_group_search_base = ou=groups,$BASE
ldap_user_search_base = ou=users,$BASE
ldap_default_authtok = 1234
ldap_tls_reqcert = demand
ldap_tls_cacert = $PATH_PKI/cacert.crt
ldap_tls_cacertdir = $PATH_PKI
ldap_search_timeout = 50
ldap_network_timeout = 60
ldap_access_order = filter
ldap_access_filter = (objectClass=posixAccount)
EOL

echo "... Configuring ldap.conf"

echo "BASE $BASE" >> /etc/openldap/ldap.conf
echo "URI ldaps://$LDAP_SERVER" >> /etc/openldap/ldap.conf
echo "TLS_CACERT      $PATH_PKI/cacert.crt" >> /etc/openldap/ldap.conf
authselect select sssd --force

# Oddjob is a helper service that creates home directories for users the first time they log in

echo "... Configuring oddjob"
# configurar oddjob ()
systemctl enable --now oddjobd
echo "session optional pam_oddjob_mkhomedir.so skel=/etc/skel/ umask=0022" >> /etc/pam.d/system-auth 
systemctl restart oddjobd

echo "... Setting permissions"

chown -R root: /etc/sssd
chmod 600 -R /etc/sssd

echo "... Starting sssd"

systemctl enable --now sssd

echo "... Done"

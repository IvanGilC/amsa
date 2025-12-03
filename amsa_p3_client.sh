#!/bin/bash

# variables
LDAP_SERVER=$1
BASE="dc=amsa,dc=udl,dc=cat"
PATH_PKI="/etc/pki/tls"

# instalamos herramientas necessarias
dnf install -y openldap-clients sssd sssd-tools authselect oddjob-mkhomedir

# descargamos archivo cacert del server y le damos permisos
curl -f http://$LDAP_SERVER:8080/cacert.pem -o $PATH_PKI/cacert.crt
sudo chmod 644 $PATH_PKI/cacert.crt

# configurar ldap
sudo bash -c "cat > /etc/openldap/ldap.conf << EOF
URI ldaps://$LDAP_SERVER
TLS_CACERT $PATH_PKI/cacert.crt
EOF"


# configurar sssd
sudo bash -c "cat > /etc/sssd/sssd.conf << EOF
[sssd]
services = nss, pam, sudo
config_file_version = 2
domains = default

[nss]

[pam]
offline_credentials_expiration = 60

[domain/default]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
access_provider = ldap
sudo_provider = ldap
cache_credentials = True

ldap_uri = ldaps://$LDAP_SERVER
ldap_search_base = $BASE
ldap_user_search_base = ou=users,$BASE
ldap_group_search_base = ou=groups,$BASE

ldap_default_bind_dn = cn=osproxy,ou=system,$BASE
ldap_default_authtok = 1234

ldap_tls_reqcert = demand
ldap_tls_cacert = $PATH_PKI/cacert.crt

ldap_id_use_start_tls = True
ldap_search_timeout = 50
ldap_network_timeout = 60

ldap_access_filter = (objectClass=posixAccount)
EOF"

# asignamos permisos al sssd
chmod 600 /etc/sssd/sssd.conf

# configuramos authselect
authselect select sssd --force

# configuramos oddjob para la creacion automatica de directorios
systemctl enable --now oddjobd
bash -c 'echo "session optional pam_oddjob_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/system-auth'

# iniciamos el sssd
systemctl enable --now sssd
#!/bin/bash

# variables necessarias
PASSWORD="1234"
VER="2.6.3"
BASE="dc=amsa,dc=udl,dc=cat"
PATH_PKI="/etc/pki/tls"
DC="amsa"
HOSTNAME="${HOSTNAME_OVERRIDE:-$HOSTNAME}"

# instalamos herramientas necessarias para usar LDAP
dnf install \
 cyrus-sasl-devel make libtool autoconf libtool-ltdl-devel \
 openssl-devel libdb-devel tar gcc perl perl-devel wget vim screen -y

# descargamos e instalamos el paquete OpenLDAP con las configuraciones necesarias
cd /tmp
cat << EOL >> install-ldap.sh
#!/bin/bash
wget ftp://ftp.openldap.org/pub/OpenLDAP/openldap-release/openldap-$VER.tgz
tar xzf openldap-$VER.tgz
cd openldap-$VER
    ./configure --prefix=/usr --sysconfdir=/etc --disable-static \
    --enable-debug --with-tls=openssl --with-cyrus-sasl --enable-dynamic \
    --enable-crypt --enable-spasswd --enable-slapd --enable-modules \
    --enable-rlookups  --disable-sql  \
    --enable-ppolicy --enable-syslog
make depend
make
cd contrib/slapd-modules/passwd/sha2
make
cd ../../../..
make install
cd contrib/slapd-modules/passwd/sha2
make install
EOL
bash install-ldap.sh

# creacion de usuario/grupo para gestionar el demonio
groupadd -g 55 ldap
useradd -r -M -d /var/lib/openldap -u 55 -g 55 -s /usr/sbin/nologin ldap

# configuracion del servicio
mkdir /var/lib/openldap
mkdir /etc/openldap/slapd.d
chown -R ldap:ldap /var/lib/openldap
chown root:ldap /etc/openldap/slapd.conf
chmod 640 /etc/openldap/slapd.conf

# fichero de configuracion de LDAP
sudo bash -c "cat > /etc/systemd/system/slapd.service << 'EOL'
[Unit]
Description=OpenLDAP Server Daemon
After=syslog.target network-online.target
Documentation=man:slapd
Documentation=man:slapd-mdb

[Service]
Type=forking
PIDFile=/var/lib/openldap/slapd.pid
Environment=\"SLAPD_URLS=ldap:/// ldapi:/// ldaps:///\"
Environment=\"SLAPD_OPTIONS=-F /etc/openldap/slapd.d\"
ExecStart=/usr/libexec/slapd -u ldap -g ldap -h \${SLAPD_URLS} \$SLAPD_OPTIONS

[Install]
WantedBy=multi-user.target
EOL"

mv /etc/openldap/slapd.ldif /etc/openldap/slapd.ldif.default

# generacion de contrasenas con SHA-512
HASH=$(slappasswd -h "{SSHA512}" -s $PASSWORD -o module-load=pw-sha2.la -o module-path=/usr/local/libexec/openldap)

# CREACION DE BASE DE DATOS
# creamos un fichero de configuracion
cat << EOL >> /etc/openldap/slapd.ldif
dn: cn=config
objectClass: olcGlobal
cn: config
olcArgsFile: /var/lib/openldap/slapd.args
olcPidFile: /var/lib/openldap/slapd.pid
olcTLSCipherSuite: TLSv1.2:HIGH:!aNULL:!eNULL
olcTLSProtocolMin: 3.3

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulepath: /usr/libexec/openldap
olcModuleload: back_mdb.la

dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulepath: /usr/local/libexec/openldap
olcModuleload: pw-sha2.la

include: file:///etc/openldap/schema/core.ldif
include: file:///etc/openldap/schema/cosine.ldif
include: file:///etc/openldap/schema/nis.ldif
include: file:///etc/openldap/schema/inetorgperson.ldif

dn: olcDatabase=frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: frontend
olcPasswordHash: $HASH
olcAccess: to dn.base="cn=Subschema" by * read
olcAccess: to *
  by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
  by * none

dn: olcDatabase=config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: config
olcRootDN: cn=config
olcAccess: to *
  by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
  by * none
EOL

# cargamos la configuracion a la base de datos
cd /etc/openldap/
slapadd -n 0 -F /etc/openldap/slapd.d -l /etc/openldap/slapd.ldif
chown -R ldap:ldap /etc/openldap/slapd.d

# iniciamos el servicio
systemctl daemon-reload
systemctl enable --now slapd

# configuracion en la estructura de la base de datos un usuario admin
cat << EOL >> /etc/openldap/rootdn.ldif
dn: olcDatabase=mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: mdb
olcDbMaxSize: 42949672960
olcDbDirectory: /var/lib/openldap
olcSuffix: $BASE
olcRootDN: cn=admin,$BASE
olcRootPW: $HASH
olcDbIndex: uid pres,eq
olcDbIndex: cn,sn pres,eq,approx,sub
olcDbIndex: mail pres,eq,sub
olcDbIndex: objectClass pres,eq
olcDbIndex: loginShell pres,eq
olcAccess: to attrs=userPassword,shadowLastChange,shadowExpire
  by self write
  by anonymous auth
  by dn.subtree="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
  by dn.subtree="ou=system,$BASE" read
  by * none
olcAccess: to dn.subtree="ou=system,$BASE"
  by dn.subtree="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
  by * none
olcAccess: to dn.subtree="$BASE"
  by dn.subtree="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
  by users read
  by * none
EOL

# cargamos la configuracion en la base de datos
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/rootdn.ldif

# creamos la configuracion para usuarios y grupos
cat << EOL >> /etc/openldap/basedn.ldif
dn: $BASE
objectClass: dcObject
objectClass: organization
objectClass: top
o: AMSA
dc: $DC

dn: ou=groups,$BASE
objectClass: organizationalUnit
objectClass: top
ou: groups

dn: ou=users,$BASE
objectClass: organizationalUnit
objectClass: top
ou: users

dn: ou=system,$BASE
objectClass: organizationalUnit
objectClass: top
ou: system
EOL

# cargamos la configuracion en la base de datos
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/basedn.ldif

# creacion de usuario OSProxy
cat << EOL >> /etc/openldap/users.ldif
dn: cn=osproxy,ou=system,$BASE
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: osproxy
userPassword: $HASH
description: OS proxy for resolving UIDs/GIDs
EOL

groups=("programadors" "dissenyadors")
gids=("4000" "5000")
users=("ramon" "manel")
sns=("mateo" "lopez")
uids=("4001" "5001")

for (( j=0; j<${#groups[@]}; j++ ))
do
cat << EOL >> /etc/openldap/users.ldif
dn: cn=${groups[$j]},ou=groups,$BASE
objectClass: posixGroup
cn: ${groups[$j]}
gidNumber: ${gids[$j]}
EOL
done

for (( j=0; j<${#users[@]}; j++ ))
do
cat << EOL >> /etc/openldap/users.ldif
dn: uid=${users[$j]},ou=users,$BASE
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: ${users[$j]}
sn: ${sns[$j]}
uid: ${users[$j]}
uidNumber: ${uids[$j]}
gidNumber: ${uids[$j]}
homeDirectory: /home/${users[$j]}
loginShell: /bin/bash
userPassword: $HASH
EOL
done

# cargamos la configuracion en la base de datos
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/users.ldif

# configuramos los certificados tls
commonname=$HOSTNAME
country=ES
state=Spain
locality=Igualada
organization=UdL
organizationalunit=IT
email=admin@udl.cat

openssl req -days 500 -newkey rsa:4096 \
    -keyout "$PATH_PKI/ldapkey.pem" -nodes \
    -sha256 -x509 -out "$PATH_PKI/ldapcert.pem" \
    -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"

# otorgamos los permisos necessarios
chown ldap:ldap "$PATH_PKI/ldapkey.pem"
chmod 400 "$PATH_PKI/ldapkey.pem"
cp "$PATH_PKI/ldapcert.pem" "$PATH_PKI/cacerts.pem"

# creamos el fichero add-tls
cat << EOL >> /etc/openldap/add-tls.ldif
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: "$PATH_PKI/cacerts.pem"
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: "$PATH_PKI/ldapkey.pem"
-
add: olcTLSCertificateFile
olcTLSCertificateFile: "$PATH_PKI/ldapcert.pem"
EOL

# cargamos la configuracion
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/add-tls.ldif

# reiniciamos el servicio LDAP
systemctl restart slapd

# INSTALAMOS CLIENTE WEB DE LDAP
# instalamos dependencias de LAM
dnf install -y httpd php php-ldap php-mbstring php-gd php-gmp php-zip
systemctl enable --now httpd

# descargamos y descomprimimos LAM
wget https://github.com/LDAPAccountManager/lam/releases/download/9.0.RC1/ldap-account-manager-9.0.RC1-0.fedora.1.noarch.rpm
dnf install -y ldap-account-manager-9.0.RC1-0.fedora.1.noarch.rpm

# configuramos LAM
rm /var/lib/ldap-account-manager/config/config.cfg
cat << EOL >> /var/lib/ldap-account-manager/config/config.cfg
{
    "password": "{CRYPT-SHA512}$6$rsgKmrlAp8i9Yz8m$kkaxMk7FT4CO4j7nj3u7ThAoSN9VbRE36TwErLZsAawz6ocviCYecI9dcuZyY.MbcGOf9gR0QWJA2qOkP5YV\/. cnNnS21ybEFwOGk5WXo4bQ==",
    "default": "lam",
    "sessionTimeout": "30",
    "hideLoginErrorDetails": "false",
    "logLevel": "4",
    "logDestination": "SYSLOG",
    "allowedHosts": "",
    "passwordMinLength": "10",
    "passwordMinUpper": "0",
    "passwordMinLower": "0",
    "passwordMinNumeric": "0",
    "passwordMinClasses": "0",
    "passwordMinSymbol": "0",
    "checkedRulesCount": "-1",
    "passwordMustNotContainUser": "false",
    "passwordMustNotContain3Chars": "false",
    "externalPwdCheckUrl": "",
    "errorReporting": "default",
    "allowedHostsSelfService": "",
    "license": "",
    "licenseEmailFrom": "",
    "licenseEmailTo": "",
    "licenseWarningType": "all",
    "licenseEmailDateSent": "",
    "mailServer": "",
    "mailUser": "",
    "mailPassword": "",
    "mailEncryption": "TLS",
    "mailAttribute": "mail",
    "mailBackupAttribute": "passwordselfresetbackupmail",
    "configDatabaseType": "files",
    "configDatabaseServer": "",
    "configDatabasePort": "",
    "configDatabaseName": "",
    "configDatabaseUser": "",
    "configDatabasePassword": "",
    "moduleSettings": "eyJyZXF1ZXN0QWNjZXNzIjp7Imhpc3RvcnlSZXRlbnRpb25QZXJpb2QiOiIzNjUwIiwiZXhwaXJhdGlvblBlcmlvZCI6IjMwIn19"
}
EOL

rm /var/lib/ldap-account-manager/config/lam.conf
cat << EOL >> /var/lib/ldap-account-manager/config/lam.conf
{
    "ServerURL": "ldap:\/\/localhost:389",
    "useTLS": "no",
    "followReferrals": "false",
    "pagedResults": "false",
    "Passwd": "{CRYPT-SHA512}$6$AwmbN3Cf.UCisUwB$lKScmMUGuEnBd3pQj83enFGSpMcPMZsghiF2IGR9noaYYjgfuhGDFC7NeJxppDSvIiIjs23wehB.Z6TBaP7zN1 QXdtYk4zQ2YuVUNpc1V3Qg==",
    "Admins": "cn=osproxy,ou=system,dc=amsa,dc=udl,dc=cat",
    "defaultLanguage": "en_GB.utf8",
    "scriptPath": "",
    "scriptServer": "",
    "scriptRights": "750",
    "serverDisplayName": "",
    "activeTypes": "user,group",
    "accessLevel": "100",
    "loginMethod": "list",
    "loginSearchSuffix": "dc=yourdomain,dc=org",
    "loginSearchFilter": "uid=%USER%",
    "searchLimit": "0",
    "lamProMailFrom": "noreply@example.com",
    "lamProMailReplyTo": "",
    "lamProMailSubject": "Your password was reset",
    "lamProMailText": "Dear @@givenName@@ @@sn@@,+::++::+your password was reset to: @@newPassword@@+::++::++::+Best regards+::++::+deskside support+::+",        
    "lamProMailIsHTML": "false",
    "lamProMailAllowAlternateAddress": "true",
    "httpAuthentication": "false",
    "loginSearchDN": "",
    "loginSearchPassword": "",
    "timeZone": "Europe\/London",
    "jobsBindUser": null,
    "jobsBindPassword": null,
    "jobsDatabase": null,
    "jobsDBHost": null,
    "jobsDBPort": null,
    "jobsDBUser": null,
    "jobsDBPassword": null,
    "jobsDBName": null,
    "pwdResetAllowSpecificPassword": "true",
    "pwdResetAllowScreenPassword": "true",
    "pwdResetForcePasswordChange": "true",
    "pwdResetDefaultPasswordOutput": "2",
    "scriptUserName": "",
    "scriptSSHKey": "",
    "scriptSSHKeyPassword": "",
    "twoFactorAuthentication": "none",
    "twoFactorAuthenticationURL": "https:\/\/localhost",
    "twoFactorAuthenticationInsecure": false,
    "twoFactorAuthenticationLabel": "",
    "twoFactorAuthenticationOptional": false,
    "twoFactorAuthenticationCaption": "",
    "twoFactorAuthenticationClientId": "",
    "twoFactorAuthenticationSecretKey": "",
    "twoFactorAuthenticationDomain": "",
    "twoFactorAuthenticationAttribute": "uid",
    "twoFactorAllowToRememberDevice": "false",
    "twoFactorRememberDeviceDuration": "28800",
    "twoFactorRememberDevicePassword": "uZ0TJJUrHtUO6VcVFouw9zlk0zMRtV",
    "referentialIntegrityOverlay": "false",
    "hidePasswordPromptForExpiredPasswords": "false",
    "hideDnPart": "",
    "pwdPolicyMinLength": "",
    "pwdPolicyMinLowercase": "",
    "pwdPolicyMinUppercase": "",
    "pwdPolicyMinNumeric": "",
    "pwdPolicyMinSymbolic": "",
    "typeSettings": {
        "suffix_user": "ou=users,dc=amsa,dc=udl,dc=cat",
        "attr_user": "#uid;#givenName;#sn;#uidNumber;#gidNumber",
        "modules_user": "inetOrgPerson,posixAccount,shadowAccount",
        "suffix_group": "ou=groups,dc=amsa,dc=udl,dc=cat",
        "attr_group": "#cn;#gidNumber;#memberUID;#description",
        "modules_group": "posixGroup",
        "customLabel_user": "",
        "filter_user": "",
        "customLabel_group": "",
        "filter_group": "",
        "hidden_user": false,
        "hidden_group": false
    },
    "moduleSettings": {
        "posixAccount_user_minUID": [
            "10000"
        ],
        "posixAccount_user_maxUID": [
            "30000"
        ],
        "posixAccount_host_minMachine": [
            "50000"
        ],
        "posixAccount_host_maxMachine": [
            "60000"
        ],
        "posixGroup_group_minGID": [
            "10000"
        ],
        "posixGroup_group_maxGID": [
            "20000"
        ],
        "posixAccount_user_uidGeneratorUsers": [
            "range"
        ],
        "posixAccount_host_uidGeneratorUsers": [
            "range"
        ],
        "posixAccount_group_gidGeneratorUsers": [
            "range"
        ],
        "posixGroup_pwdHash": [
            "SSHA"
        ],
        "posixAccount_pwdHash": [
            "SSHA"
        ]
    },
    "toolSettings": {
        "treeViewSuffix": "dc=amsa,dc=udl,dc=cat",
        "tool_hide_toolFileUpload": "false",
        "tool_hide_ImportExport": "false",
        "tool_hide_toolMultiEdit": "false",
        "tool_hide_toolOUEditor": "false",
        "tool_hide_toolPDFEditor": "false",
        "tool_hide_toolProfileEditor": "false",
        "tool_hide_toolSchemaBrowser": "false",
        "tool_hide_toolServerInformation": "false",
        "tool_hide_toolTests": "false",
        "tool_hide_TreeViewTool": "false",
        "tool_hide_toolWebauthn": "false"
    },
    "jobSettings": []
}
EOL
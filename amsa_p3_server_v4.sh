#!/bin/bash

# variables necessarias
PASSWORD=$1
VER="2.6.3"
BASE="dc=amsa,dc=udl,dc=cat"
PATH_PKI="/etc/pki/tls"
DC="amsa"

# instalamos herramientas necessarias para usar LDAP
dnf install \
 cyrus-sasl-devel make libtool autoconf libtool-ltdl-devel \
 openssl-devel libdb-devel tar gcc perl perl-devel wget vim screen -y

# descargamos e instalamos el paquete OpenLDAP con las configuraciones necesarias
cd /tmp
cat > install-ldap.sh << EOL
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
bash -c "cat > /etc/systemd/system/slapd.service << 'EOL'
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

# generacion de contrasenas con SHA-512
HASH=$(slappasswd -h "{SSHA512}" -s $PASSWORD -o module-load=pw-sha2.la -o module-path=/usr/local/libexec/openldap)

# CREACION DE BASE DE DATOS
# creamos un fichero de configuracion
bash -c "cat > /etc/openldap/slapd.ldif << EOL
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
olcAccess: to dn.base=\"cn=Subschema\" by * read
olcAccess: to *
  by dn.base=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" manage
  by * none

dn: olcDatabase=config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: config
olcRootDN: cn=config
olcAccess: to *
  by dn.base=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" manage
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
cat > /etc/openldap/rootdn.ldif << EOL
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
  by dn.subtree=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" manage
  by dn.subtree=\"ou=system,$BASE\" read
  by * none
olcAccess: to dn.subtree=\"ou=system,$BASE\"
  by dn.subtree=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" manage
  by * none
olcAccess: to dn.subtree=\"$BASE\"
  by dn.subtree=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" manage
  by users read
  by * none
EOL"

# cargamos la configuracion en la base de datos
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/rootdn.ldif

# creamos la configuracion para usuarios y grupos
bash -c "cat >> /etc/openldap/basedn.ldif << EOL
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
EOL"

# cargamos la configuracion en la base de datos
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/basedn.ldif

# CREACION DE USUARIOS Y ROLES
groups=("alumne" "profesor" "admin")
gids=("4000" "5000" "6000")
users=("user1" "user2" "user3" "user4" "user5" "user6" "user7" "user8" "user9")
sns=("alumno1" "alumno2" "alumno3" "alumno4" "alumno5" "alumno6" "profesor1" "profesor2" "administrador")
uids=("4001" "4002" "4003" "4004" "4005" "4006" "5001" "5002" "6001")
guids=("4000" "4000" "4000" "4000" "4000" "4000" "5000" "5000" "6000")

# Crear de usuarios osproxy
bash -c "cat > /etc/openldap/users.ldif << EOL
dn: cn=osproxy,ou=system,$BASE
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: osproxy
userPassword: $HASH
description: OS proxy for resolving UIDs/GIDs

EOL"

# Creacion de grupos
for (( j=0; j<${#groups[@]}; j++ )); do
bash -c "cat >> /etc/openldap/users.ldif << EOL
dn: cn=${groups[$j]},ou=groups,$BASE
objectClass: posixGroup
cn: ${groups[$j]}
gidNumber: ${gids[$j]}

EOL"
done

# Creacion de usuarios
for (( j=0; j<${#users[@]}; j++ )); do
bash -c "cat >> /etc/openldap/users.ldif << EOL
dn: uid=${users[$j]},ou=users,$BASE
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: ${users[$j]}
sn: ${sns[$j]}
uid: ${users[$j]}
uidNumber: ${uids[$j]}
gidNumber: ${guids[$j]}
homeDirectory: /home/${users[$j]}
loginShell: /bin/bash
userPassword: $HASH

EOL"
done

# cargamos la configuracion en la base de datos
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/users.ldif

# conseguimos el hostname
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 3600")

HOSTNAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
      http://169.254.169.254/latest/meta-data/public-hostname)

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
cp "$PATH_PKI/ldapcert.pem" "$PATH_PKI/cacert.pem"

# creamos el fichero add-tls
bash -c "cat > /etc/openldap/add-tls.ldif << EOL
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: "$PATH_PKI/cacert.pem"
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: "$PATH_PKI/ldapkey.pem"
-
add: olcTLSCertificateFile
olcTLSCertificateFile: "$PATH_PKI/ldapcert.pem"
EOL"

chown ldap:ldap "$PATH_PKI/cacert.pem"
chmod 640 "$PATH_PKI/cacert.pem"

# cargamos la configuracion
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/add-tls.ldif

# reiniciamos el servicio LDAP
systemctl restart slapd

# INSTALAMOS CLIENTE WEB DE LDAP
# instalamos dependencias de LAM
dnf install -y httpd php php-ldap php-mbstring php-gd php-gmp php-zip
systemctl enable --now httpd

# descargamos y descomprimimos LAM
wget https://github.com/LDAPAccountManager/lam/releases/download/9.0.RC1/ldap-account-manager-9.0.RC1-0.fedora.1.noarch.rpm
dnf install -y ldap-account-manager-9.0.RC1-0.fedora.1.noarch.rpm
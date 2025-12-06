#!/bin/bash

# configuramos LAM
bash -c 'cat > /var/lib/ldap-account-manager/config/lam.conf << 'EOL'
{
    "ServerURL": "ldap:\/\/localhost:389",
    "useTLS": "no",
    "followReferrals": "false",
    "pagedResults": "false",
    "Passwd": "{CRYPT-SHA512}$6$zvb8WVEHSAKEGtGO$573kA9Us8LtGLLm5Gu87P\/vIiF\/2Ol\/DauzPmUpvC4eCL\/t0WWiwBaY19Rx5G3wzbeZWWlE1kp2fikrpZTZ51\/ enZiOFdWRUhTQUtFR3RHTw==",
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
EOL'
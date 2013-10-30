AD-LDAP-Sync-Script
===================

A Python script that pull information from an Active Directory or LDAP servers and imports the changes to the MailRoute Control Panel.

Requirements
------------

* python-ldap


License
-------

Apache 2.0 License.  See LICENSE for details.


Data format
-----------
If you want to write your own data provider you just need to 
post jsoned data at "https://admin.mailroute.net/api/v1/ldapsync/remote_data/?domain=your_domain" with the following format:
```
[
    {'email': 'email1', 'aliases': ['alias1', 'alias2']},
    {'email': 'email2', 'aliases': ['alias3', 'alias3']},
]
```

Basic authorisation is used. Set "Authorization" header with following data:
```
ApiKey api_username:api_key
```


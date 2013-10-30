#!/usr/bin/env python

import collections
import json
import logging
import argparse
import urllib2
import ldap
from ldap.controls import SimplePagedResultsControl

logger = logging.getLogger(__name__)


class AbstractParser(object):
    name = 'Abstract parser'
    header = []

    def __init__(self, header=None):
        if header is not None:
            self.header = header
        self._check_header()

    def set_header(self, header):
        self.header = header
        self._check_header()

    def get_header(self):
        return self.header

    def parse(self, limit=None):
        raise NotImplementedError('You must implement this method yourself')

    def _check_header(self):
        duplicates = [x for x, y in collections.Counter(self.header).items()
                      if y > 1]
        if duplicates:
            raise ValueError('Header contain duplicated entries: %s'
                             % duplicates)

    def _process_row(self, row):
        result = collections.OrderedDict()
        for k, v in row.iteritems():
            if isinstance(v, basestring):
                v = v.strip()
            if hasattr(self, 'prepare_%s' % k):
                v = getattr(self, 'prepare_%s' % k)(v)
            result[k] = v

        return result


class ADParser(AbstractParser):
    name = 'Active Directory'
    header = [
        'email',
        'aliases',
    ]
    page_size = 500  # not more then 1000

    def __init__(self, dc_list, base_dn, user, password, port=389, use_ssl=False,
                 user_filter=None, mail_attr='mail', aliases_attrs=None):
        """
        `dc_list`: list of domain controller addresses
        `user`: Username to use (either cn=blah,dc=cust,dc=local or blah@cust.local format), no special privilegies needed
        `ou`: Org Unit (Base DN) to export from, e.g. dc=ad,dc=redrobot-studio,dc=com
        `use_ssl`: use LDAP over ssl (LDAPS)
        `mail_attr`: ldap attribute that store email
        `aliases_attrs`: list of ldap attributes that store email aliases
        """
        super(ADParser, self).__init__()
        if use_ssl:
            proto = 'ldaps'
        else:
            proto = 'ldap'

        self.ldap_servers = []

        if not isinstance(dc_list, list):
            raise TypeError('dc_list should be a list not %s' % type(dc_list))

        for dc in dc_list:
            self.ldap_servers.append('%s://%s:%s' % (proto, dc, port))

        self.bind_DN = user
        self.bind_pwd = password

        self.user_filter = user_filter or "(& (mailnickname=*)(!(mailnickname=discoverysearchmailbox*))(!(mailnickname=federatedemail*))(!(mailnickname=systemmailbox*)) " \
                                          "(| (objectClass=publicFolder)" \
                                          "(&(objectCategory=person)" \
                                          "(objectClass=user)" \
                                          "(!(homeMDB=*))" \
                                          "(!(msExchHomeServerName=*)))" \
                                          "(&(objectCategory=person)" \
                                          "(objectClass=user)" \
                                          "(|(homeMDB=*)" \
                                          "(msExchHomeServerName=*)))" \
                                          "(objectCategory=person)" \
                                          "(objectCategory=group)" \
                                          "(objectClass=msExchDynamicDistributionList) ) " \
                                          "(!(objectClass=contact)) )"
        self.base_dn = base_dn
        self.use_ssl = use_ssl

        self.mail_attr = str(mail_attr)
        if not aliases_attrs:
            aliases_attrs = ['proxyAddresses']
        self.aliases_attrs = [str(a) for a in aliases_attrs]

        self.error = None

    def parse(self, limit=None, page_size=None):
        parsed = []

        binded = self._ldap_bind()
        if binded:
            accounts = self._get_ldap_data(limit, page_size)

            self._ldap_unbind()

            entry_count = 0
            for entry in accounts:
                if hasattr(entry[1], 'has_key'):
                    aliases = []
                    for key in self.aliases_attrs:
                        for alias in entry[1].get(key, []):
                            if alias not in aliases:
                                aliases.append(alias)
                    mail = entry[1].get(self.mail_attr, '')

                    if mail:
                        row = self._process_row({'email': mail,
                                                 'aliases': aliases})
                        parsed.append(row)

                        entry_count += 1
                        if limit and (limit <= entry_count):
                            break

        return parsed

    def prepare_email(self, val):
        return val[0].lower()

    def prepare_aliases(self, val):
        aliases = []
        for addr in val:
            if 'x400:' in addr.lower():
                continue

            if ' ' in addr.lower():
                continue

            if 'smtp:' in addr.lower():
                aliases.append(addr.lower().split('smtp:')[1])
            else:
                aliases.append(addr.lower())

        return aliases

    def _set_error_from_ldap_exc(self, exc):
        _, text = str(exc).split("'desc': ")
        self.error = text.strip('}').strip('"').strip('\'')

    def _get_ldap_data(self, limit=None, page_size=None):
        page_size = page_size or self.page_size
        paged_results_control = SimplePagedResultsControl(size=page_size,
                                                              cookie='')
        attr_list = [self.mail_attr] + self.aliases_attrs
        accounts = []
        pages = 0
        while True:
            serverctrls = [paged_results_control]
            try:
                msgid = self.ldap_connection.search_ext(self.base_dn,
                                                   ldap.SCOPE_SUBTREE,
                                                   self.user_filter,
                                                   attrlist=attr_list,
                                                   serverctrls=serverctrls)
            except ldap.LDAPError, e:
                self._set_error_from_ldap_exc(e)
                logger.warning('Error performing user paged '
                               'search: %s', str(e))
                return []

            try:
                unused_code, results, unused_msgid, serverctrls = \
                    self.ldap_connection.result3(msgid)
            except ldap.LDAPError, e:
                self._set_error_from_ldap_exc(e)
                logger.warning('Error getting user paged search '
                               'results: %s', str(e))
                return []

            for result in results:
                accounts.append(result)

            cookie = None
            for serverctrl in serverctrls:
                if serverctrl.controlType == ldap.CONTROL_PAGEDRESULTS:
                    unused_est, cookie = serverctrl.size, serverctrl.cookie
                    if cookie:
                        paged_results_control.cookie = cookie
                        paged_results_control.size = page_size
                    break

            pages += 1

            if not cookie:
                break

            if limit and (limit <= page_size * pages):
                break

        return accounts

    def _process_row(self, row):
        row = super(ADParser, self)._process_row(row)
        # remove self from aliases
        row['aliases'] = [a for a in row['aliases'] if a != row['email']]

        if '@' in row['email']:
            localpart = row['email'].split('@')[0]
            row['aliases'] = [a for a in row['aliases'] if a != localpart]

        return row

    def _ldap_bind(self):
        ldap_connection = None
        failed_connections = 0
        for server in self.ldap_servers:
            try:
                if self.use_ssl:
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                                    ldap.OPT_X_TLS_NEVER)
                ldap_connection = ldap.initialize(server)
                ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
                ldap_connection.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                if self.use_ssl:
                    ldap_connection.set_option(ldap.OPT_X_TLS,
                                               ldap.OPT_X_TLS_DEMAND)
                    ldap_connection.set_option(ldap.OPT_X_TLS_DEMAND, True)
                ldap_connection.set_option(ldap.OPT_DEBUG_LEVEL, 255)
                ldap_connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 5.0)
                ldap_connection.set_option(ldap.OPT_TIMEOUT, 5.0)
                ldap_connection.simple_bind_s(self.bind_DN, self.bind_pwd)
                break #stop on successfull connection
            except ldap.LDAPError, e:
                self._set_error_from_ldap_exc(e)
                logger.warning('Error connecting to LDAP server: %s', self.error)
                failed_connections += 1

        if failed_connections == len(self.ldap_servers):
            self.ldap_connection = None
            return False
        else:
            self.ldap_connection = ldap_connection
            return True

    def _ldap_unbind(self):
        # LDAP unbind
        self.ldap_connection.unbind_s()


def get_data(args):
    parser = ADParser(args.dc_list, args.dn, args.user, args.password,
                      args.port, args.ssl, args.search_string, args.mail_attr,
                      args.aliases_attrs)

    if args.verbose:
        logger.info('Connecting to LDAP server')

    data = parser.parse()

    if args.verbose:
        logger.info('Got data from LDAP server (only the first 10 accounts '
                    'shown, total accounts %s): \n%s', len(data),
                    json.dumps(data[:10], indent=4))

    if data:
        return json.dumps(data)
    else:
        if args.verbose:
            logger.info('Got nothing from LDAP server')

    return None


def post_data(data, api_username, api_key, test_run=False):
    domain = args.domain.strip('/').replace('http://', '').replace('www.', '')

    if test_run:
        test_run = 1
    else:
        test_run = 0

    url = 'https://admin.mailroute.net/api/v1/ldapsync/remote_data/?' \
          'domain=%s&test_run=%s' % (domain, test_run)

    req = urllib2.Request(url)

    authheader =  'ApiKey %s:%s' % (api_username, api_key)
    req.add_header('Authorization', authheader)
    req.add_header('content-type', 'application/json')

    f = urllib2.urlopen(req, data)

    return f.read()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sync your Active Directory users '
                                                 'with Mailroute user base. '
                                                 'Only 2 sync requests per 12 hours allowed.')
    parser.add_argument('dc_list', metavar='DC', type=str,
                       help='List of DC addresses', nargs='+')
    parser.add_argument('-d', '--dn', dest='dn', action='store',
                       help='Base DN (e.g. dc=ad,dc=youdomain,dc=com)', required=True)
    parser.add_argument('-u', '--user', dest='user', action='store',
                       help='LDAP username (format: user@domain.com or cn=user,dc=domain,dc=com)',
                       required=True)
    parser.add_argument('-p', '--password', dest='password', action='store',
                       help='LDAP password', required=True)
    parser.add_argument('--api-user', dest='api_username', action='store',
                       help='API username (format: user@domain.com)',
                       required=True)
    parser.add_argument('--api-key', dest='api_key', action='store',
                       help='API key', required=True)
    parser.add_argument('--sync-domain', dest='domain', action='store',
                       help='Sync users for this domain', required=True)
    parser.add_argument('--ssl', dest='ssl', action='store_true',
                       help='Use ssl')
    parser.add_argument('--port', dest='port', action='store',
                       help='Port', default=389, type=int)
    parser.add_argument('--mail-attr', dest='mail_attr', action='store',
                       help='Mail attribute', default='mail', type=str)
    parser.add_argument('--aliases-attr', dest='aliases_attrs', action='append',
                       help='Aliases attribute', default=[], type=str)
    parser.add_argument('--search-string', dest='search_string', action='store',
                       help='LDAP search string (leave empty for default for MS Exchange)')
    parser.add_argument('--log', dest='log', action='store',
                       help='Log file path, if not set log messages will be directed to stdout')
    parser.add_argument('-v', dest='verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--test', dest='test', action='store_true',
                       help='Test run (not saving data but ignores api limits, just for testing purposes)')

    args = parser.parse_args()

    log_format = '%(asctime)s:%(levelname)s:%(message)s'

    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO,
                            format=log_format)
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)

    data = get_data(args)

    if data is not None:
        result = ''
        if args.verbose:
            logger.info('Sending data')
        try:
            result = post_data(data, args.api_username, args.api_key,
                               test_run=args.test)
        except urllib2.HTTPError, e:
            if e.code == 429:
                logger.error('%s %s. Server responded: Too many requests (only'
                             ' 2 syncs per 12 hours allowed)', e.code, e.msg)
            else:
                logger.error('%s %s. Server responded: %s', e.code, e.msg,
                             e.read())
            exit(1)

        if args.verbose:
            logger.info('Data sent successfully')

        print result


#!/usr/bin/env python3
"""Sync your Active Directory / LDAP users to MailRoute, from your side.

MailRoute's built-in AD/LDAP sync connects to your directory server. This script
is for when you would rather not open your directory to us. It runs on a machine
inside your network and works in three steps, each its own section below:

  STEP 1  PULL     read mailboxes and aliases from your AD / LDAP server
  STEP 2  CHANGE   edit that list in customize(), if you need to
  STEP 3  SYNC     send the list to MailRoute, which makes the domain match it:
                   mailboxes in the list but not in MailRoute are ADDED,
                   mailboxes in MailRoute but not in the list are DELETED,
                   aliases, distribution-list flags and display names are updated

Step 3 previews the adds and deletes before it sends anything, and stops if the
sync would delete more than --max-deletes mailboxes (default 25). Run with
--dry-run to see the list and the preview without changing anything.

Requirements: Python 3.8+ and the ldap3 package (pip install ldap3).

Example:
  export LDAP_PASSWORD='...' MAILROUTE_API_KEY='...'
  python3 ldapsync.py dc1.example.com dc2.example.com --ssl \\
      --dn 'dc=example,dc=com' --user 'svc-mailroute@example.com' \\
      --api-user admin@example.com --sync-domain example.com --dry-run

Options can also be read from a file, one per line in --name=value form:
  python3 ldapsync.py @ldapsync.conf
"""

import argparse
import collections
import fnmatch
import getpass
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException
except ImportError:
    sys.exit('This script needs the ldap3 package: pip install ldap3')

__version__ = '2.0.0'

log = logging.getLogger('ldapsync')


class SyncError(Exception):
    pass


# =============================================================================
# STEP 1: PULL - read mailboxes and aliases from your AD / LDAP server
# =============================================================================
#
# The result is a list of records, one per mailbox, in the format the MailRoute
# API takes:
#
#   {
#     "email": "jane@example.com",                  primary address
#     "aliases": ["j.doe@example.com"],             other addresses that deliver to her
#     "is_distribution_list": false,                a list rather than a person
#     "display_name": "Jane Doe",                   names MailRoute's anti-spoofing
#     "given_name": "Jane", "surname": "Doe",       protects against impersonation
#     "_dn": "CN=Jane Doe,OU=Staff,DC=example,DC=com"  (for customize() only, never sent)
#   }

# Exchange recipients (mailboxes, mail-enabled users, groups, public folders,
# dynamic distribution lists), no contacts or system mailboxes. The same filter
# MailRoute's built-in Active Directory sync uses.
DEFAULT_SEARCH_FILTER = (
    '(& (mailnickname=*)(!(mailnickname=discoverysearchmailbox*))(!(mailnickname=federatedemail*))'
    '(!(mailnickname=systemmailbox*))(!(mail=*.local)) '
    '(| (objectClass=publicFolder)'
    '(&(objectCategory=person)(objectClass=user)(!(homeMDB=*))(!(msExchHomeServerName=*)))'
    '(&(objectCategory=person)(objectClass=user)(|(homeMDB=*)(msExchHomeServerName=*)))'
    '(objectCategory=person)(objectCategory=group)(objectClass=msExchDynamicDistributionList) ) '
    '(!(objectClass=contact)) )'
)

NAME_ATTRS = {'display_name': 'displayName', 'given_name': 'givenName', 'surname': 'sn'}

PAGE_SIZE = 500  # Active Directory returns at most 1000 entries per page

PROXY_TYPE = re.compile(r'^([A-Za-z0-9-]+):(.*)$')


def pull_from_directory(args, password):
    """STEP 1: the directory's mailboxes as a list of records."""
    return build_records(search_directory(args, password), args)


def search_directory(args, password):
    """Every matching entry, from the first domain controller that answers.

    Any LDAP error stops the run. A partial list must never reach step 3:
    every mailbox missing from it would be deleted.
    """
    tls = None
    if args.ssl or args.starttls:
        tls = ldap3.Tls(
            validate=ssl.CERT_NONE if args.insecure else ssl.CERT_REQUIRED,
            ca_certs_file=args.ca_file,
        )
    port = args.port or (636 if args.ssl else 389)
    attributes = {args.mail_attr, *args.aliases_attrs, *NAME_ATTRS.values()}
    if args.dl_attr:
        attributes.add(args.dl_attr)

    last_error = None
    for dc in args.dc_list:
        server = ldap3.Server(dc, port=port, use_ssl=args.ssl, tls=tls, get_info=ldap3.NONE, connect_timeout=10)
        try:
            conn = ldap3.Connection(
                server,
                user=args.user,
                password=password,
                read_only=True,
                raise_exceptions=True,
                auto_referrals=False,
                receive_timeout=120,
            )
            conn.open()
            if args.starttls:
                conn.start_tls()
            conn.bind()
            try:
                log.info('Reading %s from %s:%s', args.dn, dc, port)
                response = conn.extend.standard.paged_search(
                    args.dn,
                    args.search_string or DEFAULT_SEARCH_FILTER,
                    ldap3.SUBTREE,
                    attributes=sorted(attributes),
                    paged_size=PAGE_SIZE,
                    generator=False,
                )
            finally:
                conn.unbind()
        except LDAPException as e:
            last_error = e
            log.warning('%s:%s: %s', dc, port, e)
            continue
        # searchResRef entries are referrals (DomainDnsZones and the like); skip them
        return [entry for entry in response if entry.get('type') == 'searchResEntry']

    raise SyncError(f'no domain controller could be read (last error: {last_error})')


def build_records(entries, args):
    """Directory entries -> records, one per primary address."""
    records = {}
    for entry in entries:
        attrs = entry['attributes']
        raw = attr_values(attrs, args.mail_attr)
        raw.sort(key=lambda v: not v.startswith('SMTP:'))  # Exchange marks the primary address "SMTP:"
        emails = [a for a in map(smtp_address, raw) if a]
        if not emails:
            continue
        email = emails[0]

        aliases = []
        for attr in args.aliases_attrs:
            for value in attr_values(attrs, attr):
                alias = smtp_address(value)
                if alias and alias != email and alias not in aliases:
                    aliases.append(alias)

        if email in records:  # the same address on two directory objects: keep one, merge aliases
            known = records[email]['aliases']
            known.extend(a for a in aliases if a not in known)
            continue

        record = {'email': email, 'aliases': aliases, 'is_distribution_list': is_distribution_list(attrs, args)}
        for field, attr in NAME_ATTRS.items():
            values = attr_values(attrs, attr)
            record[field] = values[0].strip() if values else ''
        record['_dn'] = entry.get('dn', '')
        records[email] = record
    return list(records.values())


def attr_values(attrs, name):
    """An attribute's values as a list of str; attribute names are case-insensitive."""
    for key, value in attrs.items():
        if key.lower() == name.lower():
            values = value if isinstance(value, (list, tuple)) else [value]
            return [v.decode('utf-8', 'replace') if isinstance(v, bytes) else str(v) for v in values]
    return []


def smtp_address(value):
    """'SMTP:Jane@Example.com' -> 'jane@example.com'.

    Other proxyAddresses types (X500:, X400:, SIP:, SPO:, EUM: ...), values with
    spaces and *.local addresses give None.
    """
    value = value.strip()
    typed = PROXY_TYPE.match(value)
    if typed:
        if typed.group(1).lower() != 'smtp':
            return None
        value = typed.group(2).strip()
    value = value.lower()
    if value.count('@') != 1 or ' ' in value or value.endswith('.local'):
        return None
    local, domain = value.split('@')
    if not local or '.' not in domain:
        return None
    return value


def is_distribution_list(attrs, args):
    if not args.dl_attr:
        return False
    pattern = args.dl_value.lower()
    return any(fnmatch.fnmatchcase(v.lower(), pattern) for v in attr_values(attrs, args.dl_attr))


# =============================================================================
# STEP 2: CHANGE THE LIST - your edits go here
# =============================================================================


def customize(records):
    """Change the list before it goes to MailRoute. Return the list to sync.

    Whatever this returns IS the domain's mailbox list: an existing MailRoute
    mailbox you drop here gets deleted in step 3. Run with --dry-run after
    editing to see the result and the add/delete preview.

    Some examples; uncomment and adapt.
    """
    # Leave out service mailboxes:
    # skip = ['scanner@*', 'noreply@*', 'svc-*@*']
    # records = [r for r in records if not any(fnmatch.fnmatchcase(r['email'], p) for p in skip)]

    # Leave out everyone in a "Disabled Users" OU:
    # records = [r for r in records if 'OU=Disabled Users,' not in r['_dn']]

    # Add a mailbox that is not in the directory:
    # records.append({'email': 'legacy@example.com', 'aliases': []})

    # Drop aliases on a domain you no longer use:
    # for r in records:
    #     r['aliases'] = [a for a in r['aliases'] if not a.endswith('@old-example.com')]

    # Disabled AD accounts can also be left out in step 1, by adding this to the
    # LDAP filter (--search-string): (!(userAccountControl:1.2.840.113556.1.4.803:=2))

    return records


# =============================================================================
# STEP 3: SYNC - make MailRoute's mailbox list match yours
# =============================================================================


def sync_to_mailroute(records, args, api):
    """STEP 3: preview the changes, check them, then send the list."""
    # 3a. Which addresses belong to the domain(s) being synced (domain + its aliases),
    #     and which mailboxes MailRoute has for them now.
    domains = {name: load_domain(api, name) for name in args.domains}

    # 3b. Keep only records for those domains. MailRoute would also apply records
    #     for other domains you manage, deleting there too; keep each sync to the
    #     domains you name.
    kept, others = [], collections.Counter()
    for record in records:
        domain = record['email'].split('@')[1]
        if any(domain in names for names, _ in domains.values()):
            kept.append({k: v for k, v in record.items() if not k.startswith('_')})
        else:
            others[domain] += 1
    records = kept
    if others:
        log.info('Left out records for domains not being synced: %s',
                 ', '.join(f'{d} ({n})' for d, n in others.most_common(10)))
    if not records:
        raise SyncError('no mailboxes for the synced domain(s); nothing sent')

    # 3c. Preview: what MailRoute will add and delete.
    deletes = 0
    for name, (names, existing) in domains.items():
        wanted = {r['email'].split('@')[0] for r in records if r['email'].split('@')[1] in names}
        if not wanted:
            log.warning('%s: no mailboxes in the list, MailRoute will leave this domain alone', name)
            continue
        added, gone = sorted(wanted - existing), sorted(existing - wanted)
        deletes += len(gone)
        log.info('%s: %d mailbox(es) in the list; %d to add, %d to delete', name, len(wanted), len(added), len(gone))
        for localpart in added:
            log.info('  + %s@%s', localpart, name)
        for localpart in gone:
            log.info('  - %s@%s', localpart, name)

    if args.verbose or args.dry_run:
        print(json.dumps(records, indent=2))
    if args.dry_run:
        log.info('Dry run: nothing sent')
        return
    if deletes > args.max_deletes:
        raise SyncError(f'the sync would delete {deletes} mailboxes, more than --max-deletes {args.max_deletes}; '
                        'check the list above, then raise --max-deletes if it is right')

    # 3d. Send. MailRoute queues the sync and emails a report when it is done.
    response = api.call('POST', '/api/v1/ldapsync/remote_data/',
                        {'domain': args.domains[0], 'test_run': int(args.test)}, records)
    task_id = response['task_id']
    log.info('Sent %d mailboxes%s; MailRoute task %s', len(records), ' as a TEST run' if args.test else '', task_id)
    if args.wait <= 0:
        return

    report_id = wait_for_task(api, task_id, args.wait)
    if report_id is None:
        log.warning('MailRoute is still working after %ds; the report will be emailed when it finishes', args.wait)
    else:
        log.info('Done. Report: %s/ldap_sync/results/%s/ (also emailed)', api.base_url, report_id)


class MailRouteAPI:
    def __init__(self, base_url, username, api_key, timeout=120):
        self.base_url = base_url.rstrip('/')
        self.auth = f'ApiKey {username}:{api_key}'
        self.timeout = timeout

    def call(self, method, path, params=None, body=None):
        url = urllib.parse.urljoin(self.base_url + '/', path.lstrip('/'))
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
        request = urllib.request.Request(
            url,
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                'Authorization': self.auth,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': f'mailroute-ldapsync/{__version__}',
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as e:
            detail = e.read(300).decode('utf-8', 'replace').strip()
            if e.code == 401:
                raise SyncError('the MailRoute API rejected the API user or key (HTTP 401)') from None
            if e.code == 429:
                raise SyncError(
                    'rate limited (HTTP 429): MailRoute accepts 2 syncs per 12 hours per API user; '
                    '--test runs do not count'
                ) from None
            raise SyncError(f'{method} {path}: HTTP {e.code} {detail}') from None
        except urllib.error.URLError as e:
            raise SyncError(f'cannot reach {self.base_url}: {e.reason}') from None
        return json.loads(raw) if raw else None

    def get_all(self, path, params):
        """Every object of a list endpoint, following the pages."""
        objects = []
        page = self.call('GET', path, dict(params, limit=500))
        while True:
            objects.extend(page['objects'])
            if not page['meta'].get('next'):
                return objects
            page = self.call('GET', page['meta']['next'])


def load_domain(api, name):
    """(the domain's names: itself plus its domain aliases, its mailboxes' localparts now)."""
    domains = api.get_all('/api/v1/domain/', {'name': name})
    if not domains:
        raise SyncError(f'domain {name} is not in MailRoute, or this API user cannot manage it')
    domain_id = domains[0]['id']
    names = {name} | {a['name'].lower() for a in api.get_all('/api/v1/domain_alias/', {'domain': domain_id})}
    localparts = {a['localpart'].lower() for a in api.get_all('/api/v1/email_account/', {'domain': domain_id})}
    return names, localparts


def wait_for_task(api, task_id, seconds):
    """The sync task's result (its report id), or None if it is still running."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            state = api.call('GET', f'/api/v1/taskstate/{task_id}/')
        except SyncError as e:
            # this endpoint cannot return a failed task's error, so a failure shows up as an HTTP error
            raise SyncError(f'sync task {task_id} could not be checked, it has most likely failed ({e})') from None
        if state.get('status') == 'SUCCESS':
            return state.get('result')
        if state.get('status') in ('FAILURE', 'REVOKED'):
            raise SyncError(f'sync task {task_id} ended with {state["status"]}')
        time.sleep(5)
    return None


# =============================================================================
# Command line
# =============================================================================


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description='Sync Active Directory / LDAP mailboxes to MailRoute: adds what is new, DELETES what is gone.',
        fromfile_prefix_chars='@',
    )
    p.add_argument('dc_list', metavar='DC', nargs='+', help='domain controller / LDAP server host names')

    d = p.add_argument_group('step 1: your directory')
    d.add_argument('-d', '--dn', required=True, help='search base, e.g. dc=example,dc=com')
    d.add_argument('-u', '--user', required=True, help='bind user: user@example.com or cn=...,dc=...')
    d.add_argument('-p', '--password', help='bind password (better: the LDAP_PASSWORD environment variable)')
    d.add_argument('--ssl', action='store_true', help='LDAPS (port 636 unless --port)')
    d.add_argument('--starttls', action='store_true', help='StartTLS on the plain LDAP port')
    d.add_argument('--port', type=int, help='default 389, or 636 with --ssl')
    d.add_argument('--ca-file', help="CA certificate (PEM) for the server's certificate, if not in the system store")
    d.add_argument('--insecure', action='store_true', help='do not verify the TLS certificate')
    d.add_argument('--search-string', help='LDAP filter (default: Exchange recipients, no contacts)')
    d.add_argument('--mail-attr', default='mail', help='attribute holding the primary address (default: mail)')
    d.add_argument('--aliases-attr', dest='aliases_attrs', action='append', default=[],
                   help='attribute holding aliases, repeatable (default: proxyAddresses)')
    d.add_argument('--dl-attr', help='attribute that marks a distribution list, e.g. objectClass')
    d.add_argument('--dl-value', default='group', help='--dl-attr value of a list, wildcards allowed (default: group)')

    m = p.add_argument_group('step 3: MailRoute')
    m.add_argument('--api-user', dest='api_username', required=True, help='MailRoute API user')
    m.add_argument('--api-key', help='MailRoute API key (better: the MAILROUTE_API_KEY environment variable)')
    m.add_argument('--api-url', default='https://admin.mailroute.net', help='default https://admin.mailroute.net')
    m.add_argument('--sync-domain', dest='domains', action='append', required=True, metavar='DOMAIN',
                   help='MailRoute domain to sync, repeatable; records for other domains are left out')
    m.add_argument('--max-deletes', type=int, default=25,
                   help='stop when the sync would delete more mailboxes than this (default 25)')
    m.add_argument('--wait', type=int, default=300, metavar='SECONDS',
                   help='how long to wait for MailRoute to finish (default 300, 0 = do not wait)')

    r = p.add_argument_group('run mode')
    r.add_argument('--dry-run', action='store_true', help='pull, change and preview only; send nothing')
    r.add_argument('--test', action='store_true',
                   help='MailRoute runs the sync and emails the report, then discards every change')
    r.add_argument('--log', help='log file (default: standard error)')
    r.add_argument('-v', '--verbose', action='store_true', help='also print the list being sent')
    r.add_argument('--version', action='version', version=__version__)

    args = p.parse_args(argv)
    args.aliases_attrs = args.aliases_attrs or ['proxyAddresses']
    args.domains = [x.strip().lower() for x in args.domains]
    if args.ssl and args.starttls:
        p.error('use --ssl or --starttls, not both')
    return args


def secret(value, env_name, what):
    value = value or os.environ.get(env_name)
    if not value and sys.stdin.isatty():
        value = getpass.getpass(f'{what}: ')
    if not value:
        raise SyncError(f'no {what}: set {env_name} or pass it as an option')
    return value


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(filename=args.log, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        ldap_password = secret(args.password, 'LDAP_PASSWORD', 'LDAP password')
        api = MailRouteAPI(args.api_url, args.api_username, secret(args.api_key, 'MAILROUTE_API_KEY', 'API key'))

        records = pull_from_directory(args, ldap_password)  # STEP 1
        log.info('Step 1: %d mailboxes read from the directory', len(records))

        records = customize(records)  # STEP 2
        log.info('Step 2: %d mailboxes after customize()', len(records))

        sync_to_mailroute(records, args, api)  # STEP 3
    except SyncError as e:
        log.error('%s', e)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

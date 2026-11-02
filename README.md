# AD-LDAP-Sync-Script

Keep MailRoute's user list for your domain in step with your Active Directory or
LDAP server, without opening your directory to MailRoute.

MailRoute's built-in AD/LDAP sync connects *in* to your directory server. This
script runs *inside* your network instead: it reads your directory there, lets
you adjust the list, and sends the result to the MailRoute API over HTTPS. The
only connection it needs is outbound HTTPS to `admin.mailroute.net`.

## How it works

The script runs three steps. Each is its own section in `ldapsync.py`.

| Step | What happens | Where in `ldapsync.py` |
|---|---|---|
| **1. Pull** | Reads every mailbox, its primary address, its aliases (`proxyAddresses`) and its display name from your AD / LDAP server. | `pull_from_directory()` |
| **2. Change** | Hands that list to a function you can edit: leave out service accounts or an OU, add a mailbox that is not in the directory, drop old aliases. | `customize()` |
| **3. Sync** | Makes MailRoute's user list for the domain match yours. | `sync_to_mailroute()` |

Step 3 adds the mailboxes MailRoute doesn't have yet and **deletes the
mailboxes your list no longer contains**. It also updates aliases,
distribution-list flags and the names MailRoute's anti-spoofing protects.
Before sending anything, it shows what would be added and deleted. It stops
if the sync would delete more than `--max-deletes` mailboxes (default 25).

## Requirements

* Python 3.8 or newer (Windows, Linux or macOS)
* `pip install -r requirements.txt` (the pure-Python `ldap3` package; nothing to compile)
* A directory account that can read users. No special rights are needed.
* A MailRoute API key. Log in to the control panel, open **Settings**, and copy
  your **API Key**. The key has your login's rights: it must be able to manage
  the domain you sync.

## First run

Put the passwords in environment variables, not on the command line:

```sh
export LDAP_PASSWORD='directory password'
export MAILROUTE_API_KEY='your API key'
```

(On Windows: `set LDAP_PASSWORD=...` in cmd, or `$env:LDAP_PASSWORD='...'` in PowerShell.)

**1. Preview.** This sends nothing. It prints the list as JSON and logs every
mailbox that would be added (`+`) or deleted (`-`):

```sh
python3 ldapsync.py dc1.example.com dc2.example.com --ssl \
    --dn 'dc=example,dc=com' --user 'svc-mailroute@example.com' \
    --api-user admin@example.com --sync-domain example.com \
    --dry-run
```

**2. Adjust.** If the list isn't right, either change the search (`--search-string`,
`--mail-attr`, `--aliases-attr`) or edit `customize()` in `ldapsync.py`. The
function has commented examples. Run the preview again until the list is right.

**3. Test run.** Replace `--dry-run` with `--test`. MailRoute runs the whole
sync, emails you the report, then throws every change away. Test runs are not
rate-limited.

**4. Sync for real.** Drop `--test`. The script waits for MailRoute to finish
and prints a link to the report. MailRoute also emails the report.

## Options worth knowing

| Option | Default | Notes |
|---|---|---|
| `DC ...` | | One or more directory servers. The first one that answers is used. |
| `--ssl` / `--starttls` | off | Encrypts the connection. Use one of them: plain LDAP sends the password unencrypted. `--ssl` uses port 636. |
| `--ca-file` | system CAs | Your internal CA certificate (PEM), if the DC's certificate is not trusted by the system. `--insecure` turns verification off; avoid it. |
| `--search-string` | Exchange recipients, no contacts | Same filter as MailRoute's built-in AD sync. To skip disabled accounts, add `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`. |
| `--mail-attr` / `--aliases-attr` | `mail` / `proxyAddresses` | Only `smtp:` entries become aliases; `X500:`, `SIP:` and other address types are ignored. |
| `--dl-attr` / `--dl-value` | off / `group` | Marks entries as distribution lists, e.g. `--dl-attr objectClass`. |
| `--sync-domain` | required | Repeat it for several domains. Its domain aliases count automatically, and addresses on any other domain are left out. |
| `--max-deletes` | 25 | Raise it for one run when a large cleanup is intended. |
| `--log FILE` | standard error | |

Options can live in a file, one per line in `--name=value` form, and be read
with `python3 ldapsync.py @ldapsync.conf`. Restrict that file's permissions if
it holds a password.

## Running it on a schedule

MailRoute accepts **2 real syncs per 12 hours** per API user, so once or twice
a day is the right pace.

* Linux: `0 6 * * * /usr/bin/python3 /opt/ldapsync/ldapsync.py @/opt/ldapsync/ldapsync.conf --log /var/log/ldapsync.log`
* Windows: a Task Scheduler task that runs `python.exe C:\ldapsync\ldapsync.py @C:\ldapsync\ldapsync.conf --log C:\ldapsync\ldapsync.log`

The script exits with 0 on success and 1 on any error. On any directory error
it sends nothing, because a partial list would delete every mailbox missing
from it.

## Writing your own pull (data format)

You can skip this script and send your own list, for example one exported with
PowerShell's `Get-ADUser`. POST it as JSON to

```
https://admin.mailroute.net/api/v1/ldapsync/remote_data/?domain=example.com&test_run=0
Authorization: ApiKey <login>:<api key>
Content-Type: application/json
```

```json
[
  {"email": "jane@example.com", "aliases": ["j.doe@example.com"],
   "display_name": "Jane Doe", "given_name": "Jane", "surname": "Doe"},
  {"email": "sales@example.com", "aliases": [], "is_distribution_list": true}
]
```

Only `email` is required. The same rule applies: every mailbox of that domain
that is missing from the list is deleted. Send only addresses on the domain
you are syncing, and use `test_run=1` first.

## License

Apache 2.0. See LICENSE.

# cPanel & kernel security helper

One **`security-remediation.sh`** for **CVE-2026-41940** (cPanel), **CVE-2026-31431** (kernel "Copy Fail"), CSF, optional domain/proxy cleanup, and optional operator hardening.

**Maintainer:** [Aria Jahangiri Far](https://github.com/MrAriaNet)

---

## Clone

```bash
git clone https://github.com/MrAriaNet/cPanel-Fix.git
cd cPanel-Fix
chmod +x security-remediation.sh
sudo ./security-remediation.sh              # assess only
sudo ./security-remediation.sh --fix-all    # cPanel + kernel + merge CSF panel ports
```

Publish as a new repo under your account (e.g. `https://github.com/MrAriaNet/cPanel-Fix`) with `git init`, `git add`, `git commit`, `git push`.

---

## Flags (quick reference)

| Flag | What it does |
|------|----------------|
| *(default)* | Assess CVE/cPanel version, CSF `TCP_IN`, kernel `algif_aead` |
| `--fix-cpanel` | `upcp --force`, restart `cpsrvd`, flush session raw/cache/preauth |
| `--purge-cpanel-sessions` | Session flush + restart only |
| `--fix-kernel` | modprobe blacklist + unload `algif_aead` |
| `--fix-csf` | Merge **2083,2087,2095,2096** into `TCP_IN`, `csf -r` |
| `--csf-strip-panel-ports` | Remove lockdown port set from `TCP_IN` (**not** with `--fix-csf`) |
| `--extra-hardening-csf` | Aggressive `csf.conf` + **fixed** `TCP_IN` + `csf -r` / `csf -ra` (**not** with `--fix-csf`) |
| `--list-domains` | Print `/etc/userdomains` (`user<TAB>domain`); optional `--domain-list-output=/path` |
| `--remove-service-subdomains` | `proxydomains` + `servicedomains remove` per row |
| `--extra-hardening` | `rpcbind` off, WHM Terminal UI flag, `whmapi1` tweaks, `compilers off` |
| `--fix-all` | `--fix-cpanel` + `--fix-kernel` + `--fix-csf` only |
| `-y` / `--non-interactive` · `--dry-run` | Obvious |

**Conflicts:** script exits if you mix **`--fix-csf`** with **`--csf-strip-panel-ports`** or **`--extra-hardening-csf`**.

---

## Behaviour notes

- **cPanel:** compares **`cpanel -V`** to built-in minimum builds per line from [the advisory](https://support.cpanel.net/hc/en-us/articles/40073787579671-Security-CVE-2026-41940-cPanel-WHM-WP2-Security-Update-04-28-2026); unknown tiers → warning only.
- **CSF:** Python edits **`/etc/csf/csf.conf`** (quoted `TCP_IN`); backups use **`.bak.`** timestamps.
- **Kernel:** interim **`algif_aead`** block per [Copy Fail](https://copy.fail/#copy-fail); real fix = patched kernel package.
- **Domains:** proxy strip hits **80/443** host-style names; combine with CSF for port-level control ([proxy KB](https://support.cpanel.net/hc/en-us/articles/4405754485527-How-to-remove-service-subdomains-WHM-cPanel-Webmail-Webdisk-)).
- **Extra hardening:** checklist-style steps (WHM tweaks, etc.); **`--extra-hardening-csf`** overwrites **`TCP_IN`** with a short list - expect **no 2087 / custom apps** unless you edit the script.

---

## Examples

```bash
./security-remediation.sh --fix-kernel --dry-run
./security-remediation.sh --list-domains --domain-list-output=/root/domains.tsv
./security-remediation.sh --remove-service-subdomains
./security-remediation.sh --extra-hardening
```

---

## After a suspected breach

Use cPanel’s **`ioc_checksessions_files.sh`** from [their CVE page](https://support.cpanel.net/hc/en-us/articles/40073787579671-Security-CVE-2026-41940-cPanel-WHM-WP2-Security-Update-04-28-2026); review `/var/cpanel/sessions` and access logs.

---

## Undo

Restore **`csf.conf`** / **`csf.conf.bak.*`**, remove modprobe drop-in after a fixed kernel, follow cPanel policy if you must roll back `upcp`.

---

## References

- [CVE-2026-41940](https://support.cpanel.net/hc/en-us/articles/40073787579671-Security-CVE-2026-41940-cPanel-WHM-WP2-Security-Update-04-28-2026)
- [CVE-2026-31431](https://copy.fail/#copy-fail)
- [Qualys - CVE-2026-41940](https://threatprotect.qualys.com/2026/04/30/cpanel-and-whm-authentication-bypass-vulnerability-exploited-in-the-wild-cve-2026-41940/)

---

## Acknowledgments

**Saeed Yavari** ([@iSaeedYavari](https://t.me/iSaeedYavari)) - context and hardening checklist reflected in **`--extra-hardening`** / **`--extra-hardening-csf`**.

---

## Disclaimer

Use only on systems you administer or are authorized to test.

© Aria Jahangiri Far - [github.com/MrAriaNet](https://github.com/MrAriaNet)

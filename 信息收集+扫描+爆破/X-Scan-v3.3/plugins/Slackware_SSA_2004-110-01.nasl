# This script was automatically generated from the SSA-2004-110-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18769);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-110-01 security update');
script_set_attribute(attribute:'description', value: '
New utempter packages are available for Slackware 9.1 and -current to
fix a security issue.  (Slackware 9.1 was the first version of Slackware
to use the libutempter library, and earlier versions of Slackware are
not affected by this issue)

The utempter package provides a utility and shared library that
allows terminal applications such as xterm and screen to update
/var/run/utmp and /var/log/wtmp without requiring root privileges.
Steve Grubb has identified an issue with utempter-0.5.2 where
under certain circumstances an attacker could cause it to
overwrite files through a symlink.  This has been addressed by
upgrading the utempter package to use Dmitry V. Levin\'s new
implementation of libutempter that does not have this bug.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0233

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-110-01");
script_summary("SSA-2004-110-01 utempter security update ");
script_name(english: "SSA-2004-110-01 utempter security update ");
script_cve_id("CVE-2004-0233");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "utempter", pkgver: "1.1.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package utempter is vulnerable in Slackware 9.1
Upgrade to utempter-1.1.1-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "utempter", pkgver: "1.1.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package utempter is vulnerable in Slackware -current
Upgrade to utempter-1.1.1-i486-1 or newer.
');
}

if (w) { security_note(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

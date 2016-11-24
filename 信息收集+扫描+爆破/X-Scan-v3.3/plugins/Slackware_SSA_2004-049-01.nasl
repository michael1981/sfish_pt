# This script was automatically generated from the SSA-2004-049-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18789);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-049-01 security update');
script_set_attribute(attribute:'description', value: '
New kernels are available for Slackware 9.1 and -current to fix
a bounds-checking problem in the kernel\'s mremap() call which
could be used by a local attacker to gain root privileges.
Please note that this is not the same issue as CVE-2003-0985
which was fixed in early January.

The kernels in Slackware 8.1 and 9.0 that were updated in
January are not vulnerable to this new issue because the patch
from Solar Designer that was used to fix the CVE-2003-0985 bugs
also happened to fix the problem that was discovered later.

Sites running Slackware 9.1 or -current should upgrade to a
new kernel.  After installing the new kernel, be sure to run
\'lilo\'.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0077


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-049-01");
script_summary("SSA-2004-049-01 Kernel security update  ");
script_name(english: "SSA-2004-049-01 Kernel security update  ");
script_cve_id("CVE-2004-0077");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.24", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.24-i486-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.24", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.24-noarch-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.24", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.24-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.24", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.24-noarch-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

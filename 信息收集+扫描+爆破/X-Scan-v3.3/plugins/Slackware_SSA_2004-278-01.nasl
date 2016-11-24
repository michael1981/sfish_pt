# This script was automatically generated from the SSA-2004-278-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18776);
script_version("$Revision: 1.8 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-278-01 security update');
script_set_attribute(attribute:'description', value: '
New getmail packages are available for Slackware 9.1, 10.0 and -current to
fix a security issue.  If getmail is used as root to deliver to user owned
files or directories, it can be made to overwrite system files.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-880
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-881

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-278-01");
script_summary("SSA-2004-278-01 getmail ");
script_name(english: "SSA-2004-278-01 getmail ");
script_cve_id("CVE-2004-0880","CVE-2004-0881");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "getmail", pkgver: "3.2.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package getmail is vulnerable in Slackware 9.1
Upgrade to getmail-3.2.5-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "getmail", pkgver: "4.2.0", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package getmail is vulnerable in Slackware 10.0
Upgrade to getmail-4.2.0-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "getmail", pkgver: "4.2.0", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package getmail is vulnerable in Slackware -current
Upgrade to getmail-4.2.0-noarch-1 or newer.
');
}

if (w) { security_note(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

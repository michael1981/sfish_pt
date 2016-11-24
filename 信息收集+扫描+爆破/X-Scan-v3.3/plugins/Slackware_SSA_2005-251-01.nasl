# This script was automatically generated from the SSA-2005-251-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(19861);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2005-251-01 security update');
script_set_attribute(attribute:'description', value: '
New kdebase packages are available for Slackware 10.0, 10.1, and -current to
fix a security issue with the kcheckpass program.  Earlier versions of
Slackware are not affected.  A flaw in the way the program creates lockfiles
could allow a local attacker to gain root privileges.

For more details about the issue, see:

  http://www.kde.org/info/security/advisory-20050905-1.txt
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2494


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2005-251-01");
script_summary("SSA-2005-251-01 kcheckpass in kdebase ");
script_name(english: "SSA-2005-251-01 kcheckpass in kdebase ");
script_cve_id("CVE-2005-2494");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.0", pkgname: "kdebase", pkgver: "3.2.3", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdebase is vulnerable in Slackware 10.0
Upgrade to kdebase-3.2.3-i486-3 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "kdebase", pkgver: "3.3.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdebase is vulnerable in Slackware 10.1
Upgrade to kdebase-3.3.2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kdebase", pkgver: "3.4.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdebase is vulnerable in Slackware -current
Upgrade to kdebase-3.4.2-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

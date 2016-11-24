# This script was automatically generated from the SSA-2006-142-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21583);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-142-01 security update');
script_set_attribute(attribute:'description', value: '
New tetex packages are available for Slackware 10.2 and -current to
fix a possible security issue.  teTeX-3.0 incorporates some code from 
the xpdf program which has been shown to have various overflows that
could result in program crashes or possibly the execution of arbitrary
code as the teTeX user.  This is especially important to consider if
teTeX is being used as part of a printer filter.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3193


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-142-01");
script_summary("SSA-2006-142-01 tetex PDF security ");
script_name(english: "SSA-2006-142-01 tetex PDF security ");
script_cve_id("CVE-2005-3193");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "-current", pkgname: "tetex", pkgver: "3.0", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package tetex is vulnerable in Slackware -current
Upgrade to tetex-3.0-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "tetex-doc", pkgver: "3.0", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package tetex-doc is vulnerable in Slackware -current
Upgrade to tetex-doc-3.0-i486-2 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

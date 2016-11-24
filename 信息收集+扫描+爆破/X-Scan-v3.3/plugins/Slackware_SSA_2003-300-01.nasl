# This script was automatically generated from the SSA-2003-300-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18732);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2003-300-01 security update');
script_set_attribute(attribute:'description', value: '
GDM is the GNOME Display Manager, and is commonly used to provide
a graphical login for local users.

Upgraded gdm packages are available for Slackware 9.0, 9.1,
and -current.  These fix two vulnerabilities which could allow a local
user to crash or freeze gdm, preventing access to the machine until a
reboot.  Sites using gdm should upgrade, especially sites such as
computer labs that use gdm to provide public or semi-public access.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0793
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0794


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2003-300-01");
script_summary("SSA-2003-300-01 gdm security update ");
script_name(english: "SSA-2003-300-01 gdm security update ");
script_cve_id("CVE-2003-0793","CVE-2003-0794");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.0", pkgname: "gdm", pkgver: "2.4.1.7", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gdm is vulnerable in Slackware 9.0
Upgrade to gdm-2.4.1.7-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "gdm", pkgver: "2.4.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gdm is vulnerable in Slackware 9.1
Upgrade to gdm-2.4.4.5-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gdm", pkgver: "2.4.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gdm is vulnerable in Slackware -current
Upgrade to gdm-2.4.4.5-i486-1 or newer.
');
}

if (w) { security_note(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

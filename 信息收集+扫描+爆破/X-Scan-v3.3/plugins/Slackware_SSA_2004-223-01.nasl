# This script was automatically generated from the SSA-2004-223-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18794);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-223-01 security update');
script_set_attribute(attribute:'description', value: '
New Mozilla packages are available for Slackware 9.1, 10.0, and -current
to fix a number of security issues.  Slackware 10.0 and -current were
upgraded to Mozilla 1.7.2, and Slackware 9.1 was upgraded to Mozilla 1.4.3.
As usual, new versions of Mozilla require new versions of things that link
with the Mozilla libraries, so for Slackware 10.0 and -current new versions
of epiphany, galeon, gaim, and mozilla-plugins have also been provided.
There don\'t appear to be epiphany and galeon versions that are compatible
with Mozilla 1.4.3 and the GNOME in Slackware 9.1, so these are not
provided and Epiphany and Galeon will be broken on Slackware 9.1 if the
new Mozilla package is installed.  Furthermore, earlier versions of
Mozilla (such as the 1.3 series) were not fixed upstream, so versions
of Slackware earlier than 9.1 will remain vulnerable to these browser
issues.  If you still use Slackware 9.0 or earlier, you may want to
consider removing Mozilla or upgrading to a newer version.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

    Issues fixed in Mozilla 1.7.2:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0597
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0598
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0599
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0763
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0758

    Issues fixed in Mozilla 1.4.3:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0597
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0718
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0722
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0757
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0758
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0759
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0760
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0761
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0762
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0763
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0764
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0765


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-223-01");
script_summary("SSA-2004-223-01 Mozilla  ");
script_name(english: "SSA-2004-223-01 Mozilla  ");
script_cve_id("CVE-2004-0597","CVE-2004-0598","CVE-2004-0599","CVE-2004-0718","CVE-2004-0722","CVE-2004-0757","CVE-2004-0758","CVE-2004-0759","CVE-2004-0760","CVE-2004-0761","CVE-2004-0762","CVE-2004-0763","CVE-2004-0764","CVE-2004-0765");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "mozilla", pkgver: "1.4.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 9.1
Upgrade to mozilla-1.4.3-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mozilla-plugins", pkgver: "1.4.3", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware 9.1
Upgrade to mozilla-plugins-1.4.3-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla", pkgver: "1.7.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.0
Upgrade to mozilla-1.7.2-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla-plugins", pkgver: "1.7.2", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware 10.0
Upgrade to mozilla-plugins-1.7.2-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "epiphany", pkgver: "1.2.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package epiphany is vulnerable in Slackware 10.0
Upgrade to epiphany-1.2.7-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "gaim", pkgver: "0.81", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gaim is vulnerable in Slackware 10.0
Upgrade to gaim-0.81-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "galeon", pkgver: "1.3.17", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package galeon is vulnerable in Slackware 10.0
Upgrade to galeon-1.3.17-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla", pkgver: "1.7.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware -current
Upgrade to mozilla-1.7.2-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla-plugins", pkgver: "1.7.2", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware -current
Upgrade to mozilla-plugins-1.7.2-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "epiphany", pkgver: "1.2.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package epiphany is vulnerable in Slackware -current
Upgrade to epiphany-1.2.7-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "galeon", pkgver: "1.3.17", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package galeon is vulnerable in Slackware -current
Upgrade to galeon-1.3.17-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gaim", pkgver: "0.81", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gaim is vulnerable in Slackware -current
Upgrade to gaim-0.81-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");

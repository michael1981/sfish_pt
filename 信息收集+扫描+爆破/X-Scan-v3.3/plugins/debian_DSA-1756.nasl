# This script was automatically generated from the dsa-1756
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36066);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1756");
 script_cve_id("CVE-2009-1044", "CVE-2009-1169");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1756 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2009-1169
    Security researcher Guido Landi discovered that a XSL stylesheet could
    be used to crash the browser during a XSL transformation. An attacker
    could potentially use this crash to run arbitrary code on a victim\'s
    computer.
CVE-2009-1044
    Security researcher Nils reported via TippingPoint\'s Zero Day Initiative
    that the XUL tree method _moveToEdgeShift was in some cases triggering
    garbage collection routines on objects which were still in use. In such
    cases, the browser would crash when attempting to access a previously
    destroyed object and this crash could be used by an attacker to run
    arbitrary code on a victim\'s computer.
Note that after installing these updates, you will need to restart any
packages using xulrunner, typically iceweasel or epiphany.
As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.
For the stable distribution (lenny), these problems have been fixed in version
1.9.0.7-0lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1756');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1756] DSA-1756-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1756-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmozillainterfaces-java', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'libmozjs-dev', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'libmozjs1d', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'libmozjs1d-dbg', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'python-xpcom', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'spidermonkey-bin', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'xulrunner-1.9', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'xulrunner-1.9-dbg', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'xulrunner-1.9-gnome-support', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'xulrunner-dev', release: '5.0', reference: '1.9.0.7-0lenny2');
deb_check(prefix: 'xulrunner', release: '5.0', reference: '1.9.0.7-0lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-1751
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35989);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1751");
 script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1751 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a 
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2009-0771
    Martijn Wargers, Jesse Ruderman and Josh Soref discovered crashes
    in the layout engine, which might allow the execution of arbitrary
    code.
CVE-2009-0772
    Jesse Ruderman discovered crashes in the layout engine, which
    might allow the execution of arbitrary code.
CVE-2009-0773
    Gary Kwong, and Timothee Groleau discovered crashes in the
    Javascript engine, which might allow the execution of arbitrary code.
CVE-2009-0774
    Gary Kwong discovered crashes in the Javascript engine, which
    might allow the execution of arbitrary code. 
CVE-2009-0775
    It was discovered that incorrect memory management in the DOM
    element handling may lead to the execution of arbitrary code.
CVE-2009-0776
    Georgi Guninski discovered a violation of the same-origin policy
    through RDFXMLDataSource and cross-domain redirects.
As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.
For the stable distribution (lenny), these problems have been fixed
in version 1.9.0.7-0lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1751');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1751] DSA-1751-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1751-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmozillainterfaces-java', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'libmozjs-dev', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'libmozjs1d', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'libmozjs1d-dbg', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'python-xpcom', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'spidermonkey-bin', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'xulrunner-1.9', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'xulrunner-1.9-dbg', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'xulrunner-1.9-gnome-support', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'xulrunner-dev', release: '', reference: '1.9.0.7-0lenny1');
deb_check(prefix: 'xulrunner', release: '5.0', reference: '1.9.0.7-0lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

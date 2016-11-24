# This script was automatically generated from the dsa-1802
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38859);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1802");
 script_cve_id("CVE-2009-1381", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1802 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in SquirrelMail,
a webmail application. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2009-1578
    Cross site scripting was possible through a number of pages which
    allowed an attacker to steal sensitive session data.
    Code injection was possible when SquirrelMail was configured to
    use the map_yp_alias function to authenticate users. This is not
    the default.
CVE-2009-1580
    It was possible to hijack an active user session by planting a
    specially crafted cookie into the user\'s browser.
CVE-2009-1581
    Specially crafted HTML emails could use the CSS positioning feature
    to place email content over the SquirrelMail user interface, allowing
    for phishing.
For the old stable distribution (etch), these problems have been fixed in
version 1.4.9a-5.
For the stable distribution (lenny), these problems have been fixed in
version 1.4.15-4+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1802');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squirrelmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1802] DSA-1802-2 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1802-2 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '4.0', reference: '1.4.9a-5');
deb_check(prefix: 'squirrelmail', release: '5.0', reference: '1.4.15-4+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

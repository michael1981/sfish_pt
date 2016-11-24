# This script was automatically generated from the dsa-669
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16343);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "669");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-669 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in php4 which also apply to
the version of php3 in the stable Debian distribution.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    The memory_limit functionality allows remote attackers to execute
    arbitrary code under certain circumstances.
    The strip_tags function does not filter null (\\0) characters
    within tag names when restricting input to allowed tags, which
    allows dangerous tags to be processed by some web browsers which
    could lead to cross-site scripting (XSS) vulnerabilities.
For the stable distribution (woody) these problems have been fixed in
version 3.0.18-23.1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-669');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php3 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA669] DSA-669-1 php3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-669-1 php3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-gd', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-imap', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-ldap', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-magick', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-mhash', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-mysql', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-snmp', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-cgi-xml', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-dev', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-doc', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-gd', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-imap', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-ldap', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-magick', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-mhash', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-mysql', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-snmp', release: '3.0', reference: '3.0.18-23.1woody2');
deb_check(prefix: 'php3-xml', release: '3.0', reference: '3.0.18-23.1woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

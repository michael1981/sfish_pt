# This script was automatically generated from the dsa-1405
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(28150);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1405");
 script_cve_id("CVE-2007-5741");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1405 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that Plone, a web content management system, allows
remote attackers to execute arbitrary code via specially crafted web
browser cookies.
The oldstable distribution (sarge) is not affected by this problem.
For the stable distribution (etch) this problem has been fixed in
version 2.5.1-4etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1405');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your zope-cmfplone package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1405] DSA-1405-3 zope-cmfplone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1405-3 zope-cmfplone");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'plone-site', release: '4.0', reference: '2.5.1-4etch3');
deb_check(prefix: 'zope-cmfplone', release: '4.0', reference: '2.5.1-4etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

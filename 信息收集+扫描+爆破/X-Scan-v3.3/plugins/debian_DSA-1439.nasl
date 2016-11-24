# This script was automatically generated from the dsa-1439
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29806);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1439");
 script_cve_id("CVE-2007-6381");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1439 security update');
 script_set_attribute(attribute: 'description', value:
'Henning Pingel discovered that TYPO3, a web content management framework,
performs insufficient input sanitising, making it vulnerable to SQL
injection by logged-in backend users.


The old stable distribution (sarge) doesn\'t contain typo3-src.


For the stable distribution (etch), this problem has been fixed in
version 4.0.2+debian-4.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1439');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your typo3-src packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1439] DSA-1439-1 typo3-src");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1439-1 typo3-src");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'typo3', release: '4.0', reference: '4.0.2+debian-4');
deb_check(prefix: 'typo3-src-4.0', release: '4.0', reference: '4.0.2+debian-4');
deb_check(prefix: 'typo3-src', release: '4.0', reference: '4.0.2+debian-4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

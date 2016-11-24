# This script was automatically generated from the dsa-1499
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31143);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1499");
 script_cve_id("CVE-2008-0674");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1499 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that specially crafted regular expressions involving
codepoints greater than 255 could cause a buffer overflow in the PCRE
library (CVE-2008-0674).
For the old stable distribution (sarge), this problem has been fixed in
version 4.5+7.4-2.
For the stable distribution (etch), this problem has been fixed in
version 6.7+7.4-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1499');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pcre3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1499] DSA-1499-1 pcre3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1499-1 pcre3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpcre3', release: '3.1', reference: '4.5+7.4-2');
deb_check(prefix: 'libpcre3-dev', release: '3.1', reference: '4.5+7.4-2');
deb_check(prefix: 'pcregrep', release: '3.1', reference: '4.5+7.4-2');
deb_check(prefix: 'pgrep', release: '3.1', reference: '4.5+7.4-2');
deb_check(prefix: 'libpcre3', release: '4.0', reference: '6.7+7.4-3');
deb_check(prefix: 'libpcre3-dev', release: '4.0', reference: '6.7+7.4-3');
deb_check(prefix: 'libpcrecpp0', release: '4.0', reference: '6.7+7.4-3');
deb_check(prefix: 'pcregrep', release: '4.0', reference: '6.7+7.4-3');
deb_check(prefix: 'pcre3', release: '4.0', reference: '6.7+7.4-3');
deb_check(prefix: 'pcre3', release: '3.1', reference: '4.5+7.4-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

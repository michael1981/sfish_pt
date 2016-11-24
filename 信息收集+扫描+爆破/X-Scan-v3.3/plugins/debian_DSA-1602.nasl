# This script was automatically generated from the dsa-1602
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33403);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1602");
 script_cve_id("CVE-2008-2371");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1602 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy discovered that PCRE, the Perl-Compatible Regular
Expression library, may encounter a heap overflow condition when
compiling certain regular expressions involving in-pattern options and
branches, potentially leading to arbitrary code execution. 
For the stable distribution (etch), this problem has been fixed in
version 6.7+7.4-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1602');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pcre3 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1602] DSA-1602-1 pcre3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1602-1 pcre3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpcre3', release: '4.0', reference: '6.7+7.4-4');
deb_check(prefix: 'libpcre3-dev', release: '4.0', reference: '6.7+7.4-4');
deb_check(prefix: 'libpcrecpp0', release: '4.0', reference: '6.7+7.4-4');
deb_check(prefix: 'pcregrep', release: '4.0', reference: '6.7+7.4-4');
deb_check(prefix: 'pcre3', release: '4.0', reference: '6.7+7.4-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

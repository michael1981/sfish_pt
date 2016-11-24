# This script was automatically generated from the dsa-1432
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29705);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1432");
 script_cve_id("CVE-2007-5395");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1432 security update');
 script_set_attribute(attribute: 'description', value:
'Alin Rad Pop discovered that link-grammar, Carnegie Mellon University\'s
link grammar parser for English, performed insufficient validation within
its tokenizer, which could allow a malicious input file to execute
arbitrary code.
For the old stable distribution (sarge), this package is not present.
For the stable distribution (etch), this problem has been fixed in version
4.2.2-4etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1432');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your link-grammar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1432] DSA-1432-1 link-grammar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1432-1 link-grammar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'liblink-grammar4', release: '4.0', reference: '4.2.2-4etch1');
deb_check(prefix: 'liblink-grammar4-dev', release: '4.0', reference: '4.2.2-4etch1');
deb_check(prefix: 'link-grammar', release: '4.0', reference: '4.2.2-4etch1');
deb_check(prefix: 'link-grammar-dictionaries-en', release: '4.0', reference: '4.2.2-4etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

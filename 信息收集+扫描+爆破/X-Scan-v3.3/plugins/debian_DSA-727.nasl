# This script was automatically generated from the dsa-727
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18514);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "727");
 script_cve_id("CVE-2005-1349");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-727 security update');
 script_set_attribute(attribute: 'description', value:
'Mark Martinec and Robert Lewis discovered a buffer overflow in
Convert::UUlib, a Perl interface to the uulib library, which may
result in the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 0.201-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-727');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libconvert-uulib-perl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA727] DSA-727-1 libconvert-uulib-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-727-1 libconvert-uulib-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libconvert-uulib-perl', release: '3.0', reference: '0.201-2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

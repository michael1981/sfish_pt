# This script was automatically generated from the dsa-1522
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31628);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1522");
 script_cve_id("CVE-2008-0888");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1522 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy discovered that unzip, when processing specially crafted
ZIP archives, could pass invalid pointers to the C library\'s free
routine, potentially leading to arbitrary code execution
(CVE-2008-0888).
For the old stable distribution (sarge), this problem has been fixed
in version 5.52-1sarge5.
For the stable distribution (etch), this problem has been fixed in
version 5.52-9etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1522');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your unzip package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1522] DSA-1522-1 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1522-1 unzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge5');
deb_check(prefix: 'unzip', release: '4.0', reference: '5.52-9etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

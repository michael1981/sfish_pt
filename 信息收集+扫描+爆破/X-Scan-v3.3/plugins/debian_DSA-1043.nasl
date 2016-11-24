# This script was automatically generated from the dsa-1043
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22585);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1043");
 script_cve_id("CVE-2006-1514");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1043 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjölund discovered that abcmidi-yaps, a translator for ABC music
description files into PostScript, does not check the boundaries when
reading in ABC music files resulting in buffer overflows.
For the old stable distribution (woody) these problems have been fixed in
version 17-1woody1.
For the stable distribution (sarge) these problems have been fixed in
version 20050101-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1043');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your abcmidi-yaps package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1043] DSA-1043-1 abcmidi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1043-1 abcmidi");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'abcmidi', release: '3.0', reference: '17-1woody1');
deb_check(prefix: 'abcmidi-yaps', release: '3.0', reference: '17-1woody1');
deb_check(prefix: 'abcmidi', release: '3.1', reference: '20050101-1sarge1');
deb_check(prefix: 'abcmidi-yaps', release: '3.1', reference: '20050101-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

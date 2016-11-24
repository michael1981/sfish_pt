# This script was automatically generated from the dsa-1665
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34757);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1665");
 script_cve_id("CVE-2008-5030");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1665 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that a heap overflow in the CDDB retrieval code of 
libcdaudio, a library for controlling a CD-ROM when playing audio CDs,
may result in the execution of arbitrary code.
For the stable distribution (etch), this problem has been fixed in
version 0.99.12p2-2+etch1. A package for hppa will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1665');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libcdaudio packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1665] DSA-1665-1 libcdaudio");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1665-1 libcdaudio");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libcdaudio-dev', release: '4.0', reference: '0.99.12p2-2+etch1');
deb_check(prefix: 'libcdaudio1', release: '4.0', reference: '0.99.12p2-2+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

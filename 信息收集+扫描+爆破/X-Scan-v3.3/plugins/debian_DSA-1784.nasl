# This script was automatically generated from the dsa-1784
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38656);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1784");
 script_cve_id("CVE-2009-0946");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1784 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy discovered several integer overflows in FreeType, a library
to process and access font files, resulting in heap- or stack-based
buffer overflows leading to application crashes or the execution
of arbitrary code via a crafted font file.
For the oldstable distribution (etch), this problem has been fixed in
version 2.2.1-5+etch4.
For the stable distribution (lenny), this problem has been fixed in
version 2.3.7-2+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1784');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freetype packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1784] DSA-1784-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1784-1 freetype");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freetype2-demos', release: '4.0', reference: '2.2.1-5+etch4');
deb_check(prefix: 'libfreetype6', release: '4.0', reference: '2.2.1-5+etch4');
deb_check(prefix: 'libfreetype6-dev', release: '4.0', reference: '2.2.1-5+etch4');
deb_check(prefix: 'freetype2-demos', release: '5.0', reference: '2.3.7-2+lenny1');
deb_check(prefix: 'libfreetype6', release: '5.0', reference: '2.3.7-2+lenny1');
deb_check(prefix: 'libfreetype6-dev', release: '5.0', reference: '2.3.7-2+lenny1');
deb_check(prefix: 'freetype', release: '4.0', reference: '2.2.1-5+etch4');
deb_check(prefix: 'freetype', release: '5.0', reference: '2.3.7-2+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

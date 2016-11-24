# This script was automatically generated from the dsa-1078
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22620);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1078");
 script_cve_id("CVE-2006-2120");
 script_bugtraq_id(17809);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1078 security update');
 script_set_attribute(attribute: 'description', value:
'Andrey Kiselev discovered a problem in the TIFF library that may allow
an attacker with a specially crafted TIFF image with Yr/Yg/Yb values
that exceed the YCR/YCG/YCB values to crash the library and hence the
surrounding application.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.7.2-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1078');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tiff packages and restart the
programs using it.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1078] DSA-1078-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1078-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-4');
deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-4');
deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-4');
deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-4');
deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-4');
deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-4');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

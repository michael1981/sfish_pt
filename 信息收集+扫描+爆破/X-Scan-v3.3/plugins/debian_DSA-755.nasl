# This script was automatically generated from the dsa-755
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19189);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "755");
 script_cve_id("CVE-2005-1544");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-755 security update');
 script_set_attribute(attribute: 'description', value:
'Frank Warmerdam discovered a stack-based buffer overflow in libtiff,
the Tag Image File Format library for processing TIFF graphics files
that can lead to the execution of arbitrary code via malformed TIFF
files.
For the old stable distribution (woody) this problem has been fixed in
version 3.5.5-7.
For the stable distribution (sarge) this problem has been fixed in
version 3.7.2-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-755');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtiff packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA755] DSA-755-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-755-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-7');
deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-7');
deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-7');
deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-3');
deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

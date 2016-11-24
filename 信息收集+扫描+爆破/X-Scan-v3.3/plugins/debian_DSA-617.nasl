# This script was automatically generated from the dsa-617
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16048);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "617");
 script_cve_id("CVE-2004-1308");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-617 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" discovered a problem in libtiff, the Tag Image File
Format library for processing TIFF graphics files.  Upon reading a
TIFF file it is possible to allocate a zero sized buffer and write to
it which would lead to the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 3.5.5-6.woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-617');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtiff packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA617] DSA-617-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-617-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-6.woody3');
deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-6.woody3');
deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-6.woody3');
deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-6.woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

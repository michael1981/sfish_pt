# This script was automatically generated from the dsa-1660
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34500);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1660");
 script_cve_id("CVE-2008-3912", "CVE-2008-3913", "CVE-2008-3914");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1660 security update');
 script_set_attribute(attribute: 'description', value:
'Several denial-of-service vulnerabilities have been discovered in
the ClamAV anti-virus toolkit:
Insufficient checking for out-of-memory conditions results in null
pointer dereferences (CVE-2008-3912).
Incorrect error handling logic leads to memory leaks (CVE-2008-3913)
and file descriptor leaks (CVE-2008-3914).
For the stable distribution (etch), these problems have been fixed in
version 0.90.1dfsg-4etch15.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1660');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1660] DSA-1660-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1660-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-base', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-daemon', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-dbg', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-docs', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-freshclam', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-milter', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'clamav-testfiles', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'libclamav-dev', release: '4.0', reference: '0.90.1dfsg-4etch15');
deb_check(prefix: 'libclamav2', release: '4.0', reference: '0.90.1dfsg-4etch15');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

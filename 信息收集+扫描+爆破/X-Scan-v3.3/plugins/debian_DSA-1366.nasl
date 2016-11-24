# This script was automatically generated from the dsa-1366
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25966);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1366");
 script_cve_id("CVE-2007-4510", "CVE-2007-4560");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1366 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Clam anti-virus
toolkit. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-4510
    It was discovered that the RTF and RFC2397 parsers can be tricked
    into dereferencing a NULL pointer, resulting in denial of service.
CVE-2007-4560
    It was discovered that clamav-milter performs insufficient input
    sanitising, resulting in the execution of arbitrary shell commands.
The oldstable distribution (sarge) is only affected by a subset of 
the problems. An update will be provided later.
For the stable distribution (etch) these problems have been fixed
in version 0.90.1-3etch7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1366');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1366] DSA-1366-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1366-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-base', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-daemon', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-dbg', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-docs', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-freshclam', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-milter', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'clamav-testfiles', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'libclamav-dev', release: '4.0', reference: '0.90.1-3etch7');
deb_check(prefix: 'libclamav2', release: '4.0', reference: '0.90.1-3etch7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

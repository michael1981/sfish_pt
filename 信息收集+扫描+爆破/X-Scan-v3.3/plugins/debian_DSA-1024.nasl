# This script was automatically generated from the dsa-1024
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22566);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1024");
 script_cve_id("CVE-2006-1614", "CVE-2006-1615", "CVE-2006-1630");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1024 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the ClamAV
anti-virus toolkit, which may lead to denial of service and potentially
to the execution of arbitrary code. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2006-1614
    Damian Put discovered an integer overflow in the PE header parser.
    This is only exploitable if the ArchiveMaxFileSize option is disabled.
CVE-2006-1615
    Format string vulnerabilities in the logging code have been discovered,
    which might lead to the execution of arbitrary code.
CVE-2006-1630
    David Luyer discovered, that ClamAV can be tricked into an invalid
    memory access in the cli_bitset_set() function, which may lead to
    a denial of service.
The old stable distribution (woody) doesn\'t contain clamav packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.84-2.sarge.8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1024');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1024] DSA-1024-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1024-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.8');
deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

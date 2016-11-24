# This script was automatically generated from the dsa-1320
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25586);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1320");
 script_cve_id("CVE-2007-2650", "CVE-2007-3023", "CVE-2007-3024", "CVE-2007-3122", "CVE-2007-3123");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1320 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Clam anti-virus
toolkit. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-2650
    It was discovered that the OLE2 parser can be tricked into an infinite
    loop and memory exhaustion.
CVE-2007-3023
    It was discovered that the NsPack decompression code performed
    insufficient sanitising on an internal length variable, resulting in
    a potential buffer overflow.
CVE-2007-3024
    It was discovered that temporary files were created with insecure
    permissions, resulting in information disclosure.
CVE-2007-3122
    It was discovered that the decompression code for RAR archives allows
    bypassing a scan of a RAR archive due to insufficient validity checks.
CVE-2007-3123
    It was discovered that the decompression code for RAR archives performs
    insufficient validation of header values, resulting in a buffer overflow.
For the oldstable distribution (sarge) these problems have been fixed in
version 0.84-2.sarge.17. Please note that the fix for CVE-2007-3024 hasn\'t
been backported to oldstable.
For the stable distribution (etch) these problems have been fixed
in version 0.90.1-3etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1320');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1320] DSA-1320-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1320-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.17');
deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-base', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-daemon', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-dbg', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-docs', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-freshclam', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-milter', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav-testfiles', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'libclamav-dev', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'libclamav2', release: '4.0', reference: '0.90.1-3etch3');
deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1-3etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

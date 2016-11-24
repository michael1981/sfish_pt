# This script was automatically generated from the dsa-1340
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25782);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1340");
 script_cve_id("CVE-2007-3725");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1340 security update');
 script_set_attribute(attribute: 'description', value:
'A NULL pointer dereference has been discovered in the RAR VM of Clam
Antivirus (ClamAV) which allows user-assisted remote attackers to
cause a denial of service via a specially crafted RAR archives.
We are currently unable to provide fixed packages for the MIPS
architectures.  Those packages will be installed in the security
archive when they become available.
The old stable distribution (sarge) is not affected by this problem.
For the stable distribution (etch) this problem has been fixed in
version 0.90.1-3etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1340');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1340] DSA-1340-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1340-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-base', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-daemon', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-dbg', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-docs', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-freshclam', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-milter', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'clamav-testfiles', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'libclamav-dev', release: '4.0', reference: '0.90.1-3etch4');
deb_check(prefix: 'libclamav2', release: '4.0', reference: '0.90.1-3etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

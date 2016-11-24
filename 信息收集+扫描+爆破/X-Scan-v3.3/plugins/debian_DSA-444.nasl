# This script was automatically generated from the dsa-444
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15281);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "444");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-444 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Starzetz and Wojciech Purczynski of isec.pl <a
href="http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt">discovered</a> a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call.  Due to missing function return value check
of internal functions a local attacker can gain root privileges.
For the stable distribution (woody) this problem has been fixed in
version 011226.16 of ia64 kernel source and images.
Other architectures are or will be mentioned in a separate advisory
respectively or are not affected (m68k).
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-444');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Linux kernel packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA444] DSA-444-1 linux-kernel-2.4.17-ia64");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-444-1 linux-kernel-2.4.17-ia64");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-headers-2.4.17-ia64', release: '3.0', reference: '011226.16');
deb_check(prefix: 'kernel-image-2.4.17-itanium', release: '3.0', reference: '011226.16');
deb_check(prefix: 'kernel-image-2.4.17-itanium-smp', release: '3.0', reference: '011226.16');
deb_check(prefix: 'kernel-image-2.4.17-mckinley', release: '3.0', reference: '011226.16');
deb_check(prefix: 'kernel-image-2.4.17-mckinley-smp', release: '3.0', reference: '011226.16');
deb_check(prefix: 'kernel-source-2.4.17-ia64', release: '3.0', reference: '011226.16');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-453
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15290);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "453");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-453 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Starzetz and Wojciech Purczynski of isec.pl <a
href="http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt">discovered</a> a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call.  Due to flushing the TLB (Translation
Lookaside Buffer, an address cache) too early it is possible for an
attacker to trigger a local root exploit.
The attack vectors for 2.4.x and 2.2.x kernels are exclusive for the
respective kernel series, though.  We formerly believed that the
exploitable vulnerability in 2.4.x does not exist in 2.2.x which is
still true.  However, it turned out that a second (sort of)
vulnerability is indeed exploitable in 2.2.x, but not in 2.4.x, with a
different exploit, of course.
For the stable distribution (woody) this problem has been fixed in
the following versions and architectures:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-453');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Linux kernel package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA453] DSA-453-1 linux-kernel-2.2.20-i386+m68k+powerpc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-453-1 linux-kernel-2.2.20-i386+m68k+powerpc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-doc-2.2.20', release: '3.0', reference: '2.2.20-5woody3');
deb_check(prefix: 'kernel-headers-2.2.20', release: '3.0', reference: '2.2.20-3woody1');
deb_check(prefix: 'kernel-headers-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody5');
deb_check(prefix: 'kernel-headers-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody5');
deb_check(prefix: 'kernel-headers-2.2.20-reiserfs', release: '3.0', reference: '2.2.20-4woody1');
deb_check(prefix: 'kernel-image-2.2.20', release: '3.0', reference: '2.2.20-5woody5');
deb_check(prefix: 'kernel-image-2.2.20-amiga', release: '3.0', reference: '2.2.20-4');
deb_check(prefix: 'kernel-image-2.2.20-atari', release: '3.0', reference: '2.2.20-3');
deb_check(prefix: 'kernel-image-2.2.20-bvme6000', release: '3.0', reference: '2.2.20-3');
deb_check(prefix: 'kernel-image-2.2.20-chrp', release: '3.0', reference: '2.2.20-3woody1');
deb_check(prefix: 'kernel-image-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody5');
deb_check(prefix: 'kernel-image-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody5');
deb_check(prefix: 'kernel-image-2.2.20-mac', release: '3.0', reference: '2.2.20-3');
deb_check(prefix: 'kernel-image-2.2.20-mvme147', release: '3.0', reference: '2.2.20-3');
deb_check(prefix: 'kernel-image-2.2.20-mvme16x', release: '3.0', reference: '2.2.20-3');
deb_check(prefix: 'kernel-image-2.2.20-pmac', release: '3.0', reference: '2.2.20-3woody1');
deb_check(prefix: 'kernel-image-2.2.20-prep', release: '3.0', reference: '2.2.20-3woody1');
deb_check(prefix: 'kernel-image-2.2.20-reiserfs', release: '3.0', reference: '2.2.20-4woody1');
deb_check(prefix: 'kernel-patch-2.2.20-powerpc', release: '3.0', reference: '2.2.20-3woody1');
deb_check(prefix: 'kernel-source-2.2.20', release: '3.0', reference: '2.2.20-5woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

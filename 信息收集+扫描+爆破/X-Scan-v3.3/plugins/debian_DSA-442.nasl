# This script was automatically generated from the dsa-442
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15279);
 script_version("$Revision: 1.14 $");
 script_xref(name: "DSA", value: "442");
 script_bugtraq_id(4259);
 script_bugtraq_id(6535);
 script_bugtraq_id(7600);
 script_bugtraq_id(7601);
 script_bugtraq_id(7791);
 script_bugtraq_id(7793);
 script_bugtraq_id(7797);
 script_xref(name: "CERT", value: "981222");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-442 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been fixed in the Linux kernel
2.4.17 used for the S/390 architecture, mostly by backporting fixes
from 2.4.18 and incorporating recent security fixes.  The corrections
are listed below with the identification from the Common
Vulnerabilities and Exposures (CVE) project:
   The iBCS routines in arch/i386/kernel/traps.c for Linux kernels
   2.4.18 and earlier on x86 systems allow local users to kill
   arbitrary processes via a binary compatibility interface (lcall).
   Multiple ethernet network interface card (NIC) device drivers do
   not pad frames with null bytes, which allows remote attackers to
   obtain information from previous packets or kernel memory by using
   malformed packets, as demonstrated by Etherleak.
   The route cache implementation in Linux 2.4, and the Netfilter IP
   conntrack module, allows remote attackers to cause a denial of
   service (CPU consumption) via packets with forged source addresses
   that cause a large number of hash table collisions related to the
   PREROUTING chain.
   The ioperm system call in Linux kernel 2.4.20 and earlier does not
   properly restrict privileges, which allows local users to gain read
   or write access to certain I/O ports.
   A vulnerability in the TTY layer of the Linux kernel 2.4 allows
   attackers to cause a denial of service ("kernel oops").
   The mxcsr code in Linux kernel 2.4 allows attackers to modify CPU
   state registers via a malformed address.
   The TCP/IP fragment reassembly handling in the Linux kernel 2.4
   allows remote attackers to cause a denial of service (CPU
   consumption) via certain packets that cause a large number of hash
   table collisions.
   An integer overflow in brk() system call (do_brk() function) for
   Linux allows a local attacker to gain root privileges.  Fixed
   upstream in Linux 2.4.23.
   Paul Starzetz discovered
   a flaw in bounds checking in mremap() in
   the Linux kernel (present in version 2.4.x and 2.6.x) which may
   allow a local attacker to gain root privileges.  Version 2.2 is not
   affected by this bug.  Fixed upstream in Linux 2.4.24.
   Paul Starzetz and Wojciech Purczynski of isec.pl <a
   href="http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt">discovered</a> a
   critical security vulnerability in the memory management code of
   Linux inside the mremap(2) system call.  Due to missing function
   return value check of internal functions a local attacker can gain
   root privileges.  Fixed upstream in Linux 2.4.25 and 2.6.3.
For the stable distribution (woody) these problems have been fixed in
version 2.4.17-2.woody.3 of s390 images and in version
0.0.20020816-0.woody.2 of the patch packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-442');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Linux kernel packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA442] DSA-442-1 linux-kernel-2.4.17-s390");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
 script_summary(english: "DSA-442-1 linux-kernel-2.4.17-s390");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-2.woody.3');
deb_check(prefix: 'kernel-image-2.4.17-s390', release: '3.0', reference: '2.4.17-2.woody.3');
deb_check(prefix: 'kernel-patch-2.4.17-s390', release: '3.0', reference: '0.0.20020816-0.woody.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

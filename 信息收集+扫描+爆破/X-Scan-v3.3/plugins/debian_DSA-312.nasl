# This script was automatically generated from the dsa-312
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15149);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "312");
 script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248");
 script_bugtraq_id(6535, 7112, 7600, 7601, 7791, 7793, 7797);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-312 security update');
 script_set_attribute(attribute: 'description', value:
'A number of vulnerabilities have been discovered in the Linux kernel.
CVE-2002-0429: The iBCS routines in arch/i386/kernel/traps.c for
  Linux kernels 2.4.18 and earlier on x86 systems allow local users to
  kill arbitrary processes via a binary compatibility interface
  (lcall).
CVE-2003-0001: Multiple ethernet Network Interface Card (NIC) device
  drivers do not pad frames with null bytes, which allows remote
  attackers to obtain information from previous packets or kernel
  memory by using malformed packets.
CVE-2003-0127: The kernel module loader allows local users to gain
  root privileges by using ptrace to attach to a child process that is
  spawned by the kernel.
CVE-2003-0244: The route cache implementation in Linux 2.4, and the
  Netfilter IP conntrack module, allows remote attackers to cause a
  denial of service (CPU consumption) via packets with forged source
  addresses that cause a large number of hash table collisions related
  to the PREROUTING chain.
CVE-2003-0246: The ioperm system call in Linux kernel 2.4.20 and
  earlier does not properly restrict privileges, which allows local
  users to gain read or write access to certain I/O ports.
CVE-2003-0247: Vulnerability in the TTY layer of the Linux kernel
  2.4 allows attackers to cause a denial of service ("kernel oops").
CVE-2003-0248: The mxcsr code in Linux kernel 2.4 allows attackers
  to modify CPU state registers via a malformed address.
CVE-2003-0364: The TCP/IP fragment reassembly handling in the Linux
  kernel 2.4 allows remote attackers to cause a denial of service (CPU
  consumption) via certain packets that cause a large number of hash
  table collisions.
This advisory covers only the powerpc architecture.  Other
architectures will be covered by separate advisories.
For the stable distribution (woody) on the powerpc architecture, these
problems have been fixed in version 2.4.18-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-312');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-312
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA312] DSA-312-1 kernel-patch-2.4.18-powerpc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-312-1 kernel-patch-2.4.18-powerpc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-headers-2.4.18', release: '3.0', reference: '2.4.18-1woody1');
deb_check(prefix: 'kernel-image-2.4.18-newpmac', release: '3.0', reference: '2.4.18-1woody1');
deb_check(prefix: 'kernel-image-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody1');
deb_check(prefix: 'kernel-image-2.4.18-powerpc-smp', release: '3.0', reference: '2.4.18-1woody1');
deb_check(prefix: 'kernel-patch-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

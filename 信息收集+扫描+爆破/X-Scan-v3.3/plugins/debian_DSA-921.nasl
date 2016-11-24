# This script was automatically generated from the dsa-921
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22787);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "921");
 script_cve_id("CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2458");
 script_bugtraq_id(14477);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-921 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2005-0756
    Alexander Nyberg discovered that the ptrace() system call does not
    properly verify addresses on the amd64 architecture which can be
    exploited by a local attacker to crash the kernel.
CVE-2005-0757
    A problem in the offset handling in the xattr file system code for
    ext3 has been discovered that may allow users on 64-bit systems
    that have access to an ext3 filesystem with extended attributes to
    cause the kernel to crash.
CVE-2005-1762
    A vulnerability has been discovered in the ptrace() system call on
    the amd64 architecture that allows a local attacker to cause the
    kernel to crash.
CVE-2005-1767
    A vulnerability has been discovered in the stack segment fault
    handler that could allow a local attacker to cause a stack exception
    that will lead the kernel to crash under certain circumstances.
CVE-2005-1768
    Ilja van Sprundel discovered a race condition in the IA32 (x86)
    compatibility execve() systemcall for amd64 and IA64 that allows
    local attackers to cause the kernel to panic and possibly execute
    arbitrary code.
CVE-2005-2456
    Balazs Scheidler discovered that a local attacker could call
    setsockopt() with an invalid xfrm_user policy message which would
    cause the kernel to write beyond the boundaries of an array and
    crash.
CVE-2005-2458
    Vladimir Volovich discovered a bug in the zlib routines which are
    also present in the Linux kernel and allows remote attackers to
    crash the kernel.
CVE-2005-2459
    Another vulnerability has been discovered in the zlib routines
    which are also present in the Linux kernel and allows remote
    attackers to crash the kernel.
CVE-2005-2553
    A null pointer dereference in ptrace when tracing a 64-bit
    executable can cause the kernel to crash.
CVE-2005-2801
    Andreas Gruenbacher discovered a bug in the ext2 and ext3 file
    systems.  When data areas are to be shared among two inodes not
    all information were compared for equality, which could expose
    wrong ACLs for files.
CVE-2005-2872
    Chad Walstrom discovered that the ipt_recent kernel module to stop
    SSH bruteforce attacks could cause the kernel to crash on 64-bit
    architectures.
CVE-2005-3275
    An error in the NAT code allows remote attackers to cause a denial
    of service (memory corruption) by causing two packets for the same
    protocol to be NATed at the same time, which leads to memory
    corruption.
The following matrix explains which kernel version for which architecture
fix the problems mentioned above:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-921');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and
reboot the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA921] DSA-921-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-921-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-build-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-headers-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-generic', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-itanium', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-mckinley', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc32', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc64', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-generic', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-itanium', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-mckinley', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-s390', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-s390-tape', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-s390x', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc32', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc64', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge1');
deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-patch-2.4.27-arm', release: '3.1', reference: '2.4.27-1sarge1');
deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge1.040815-1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

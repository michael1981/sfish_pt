# This script was automatically generated from the dsa-1794
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38722);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1794");
 script_cve_id("CVE-2008-4307", "CVE-2008-5395", "CVE-2008-5701", "CVE-2008-5702", "CVE-2008-5713", "CVE-2009-0028", "CVE-2009-0029");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1794 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to denial of service, privilege escalation, or information
leak. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2008-4307
    Bryn M. Reeves reported a denial of service in the NFS filesystem.
    Local users can trigger a kernel BUG() due to a race condition in
    the do_setlk function.
CVE-2008-5395
    Helge Deller discovered a denial of service condition that allows
    local users on PA-RISC to crash the system by attempting to unwind
    a stack containing userspace addresses.
CVE-2008-5701
    Vlad Malov reported an issue on 64-bit MIPS where a local user
    could cause a system crash by crafting a malicious binary which
    makes o32 syscalls with a number less than 4000.
CVE-2008-5702
    Zvonimir Rakamaric reported an off-by-one error in the ib700wdt
    watchdog driver which allows local users to cause a buffer
    underflow by making a specially crafted WDIOC_SETTIMEOUT ioctl
    call.
CVE-2008-5713
    Flavio Leitner discovered that a local user can cause a denial of
    service by generating large amounts of traffic on a large SMP
    system, resulting in soft lockups.
CVE-2009-0028
    Chris Evans discovered a situation in which a child process can
    send an arbitrary signal to its parent.
CVE-2009-0029
    Christian Borntraeger discovered an issue effecting the alpha,
    mips, powerpc, s390 and sparc64 architectures that allows local
    users to cause a denial of service or potentially gain elevated
    privileges.
CVE-2009-0031
    Vegard Nossum discovered a memory leak in the keyctl subsystem
    that allows local users to cause a denial of service by consuming
    all available kernel memory.
CVE-2009-0065
    Wei Yongjun discovered a memory overflow in the SCTP
    implementation that can be triggered by remote users, permitting
    remote code execution.
CVE-2009-0322
    Pavel Roskin provided a fix for an issue in the dell_rbu driver
    that allows a local user to cause a denial of service (oops) by
    reading 0 bytes from a sysfs entry.
CVE-2009-0675
    Roel Kluin discovered inverted logic in the skfddi driver that
    permits local, unprivileged users to reset the driver statistics.
CVE-2009-0676
    Clement LECIGNE discovered a bug in the sock_getsockopt function
    that may result in leaking sensitive kernel memory.
CVE-2009-0834
    Roland McGrath discovered an issue on amd64 kernels that allows
    local users to circumvent system call audit configurations which
    filter based on the syscall numbers or argument details.
CVE-2009-0859
    Jiri Olsa discovered that a local user can cause a denial of
    service (system hang) using a SHM_INFO shmctl call on kernels
    compiled with CONFIG_SHMEM disabled. This issue does not affect
    prebuilt Debian kernels.
CVE-2009-1192
    Shaohua Li reported an issue in the AGP subsystem that may allow
    local users to read sensitive kernel memory due to a leak of
    uninitialized memory.
CVE-2009-1265
    Thomas Pollet reported an overflow in the af_rose implementation
    that allows remote attackers to retrieve uninitialize
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1794');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1794] DSA-1794-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1794-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '4.0', reference: '1.17+etch.24etch2');
deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-486', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-itanium', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-k7', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-prep', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-qemu', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-rpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-s390', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-s390x', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-486', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-itanium', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-k7', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-parisc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-prep', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-qemu', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-rpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-s390', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-s390x', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-image-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'linux-support-2.6.18-6', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'user-mode-linux', release: '4.0', reference: '2.6.18-1um-2etch.24etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-24etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
deb_check(prefix: 'linux-2.6', release: '4.0', reference: '2.6.18.dfsg.1-24etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

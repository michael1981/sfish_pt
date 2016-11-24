# This script was automatically generated from the dsa-1687
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35174);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1687");
 script_cve_id("CVE-2008-3527", "CVE-2008-3528", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1687 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-3527
    Tavis Ormandy reported a local DoS and potential privilege
    escalation in the Virtual Dynamic Shared Objects (vDSO)
    implementation.
CVE-2008-3528
    Eugene Teo reported a local DoS issue in the ext2 and ext3
    filesystems.  Local users who have been granted the privileges
    necessary to mount a filesystem would be able to craft a corrupted
    filesystem that causes the kernel to output error messages in an
    infinite loop.
CVE-2008-4554
    Milos Szeredi reported that the usage of splice() on files opened
    with O_APPEND allows users to write to the file at arbitrary
    offsets, enabling a bypass of possible assumed semantics of the
    O_APPEND flag.
CVE-2008-4576
    Vlad Yasevich reported an issue in the SCTP subsystem that may
    allow remote users to cause a local DoS by triggering a kernel
    oops.
CVE-2008-4933
    Eric Sesterhenn reported a local DoS issue in the hfsplus
    filesystem.  Local users who have been granted the privileges
    necessary to mount a filesystem would be able to craft a corrupted
    filesystem that causes the kernel to overrun a buffer, resulting
    in a system oops or memory corruption.
CVE-2008-4934
    Eric Sesterhenn reported a local DoS issue in the hfsplus
    filesystem.  Local users who have been granted the privileges
    necessary to mount a filesystem would be able to craft a corrupted
    filesystem that results in a kernel oops due to an unchecked
    return value.
CVE-2008-5025
    Eric Sesterhenn reported a local DoS issue in the hfs filesystem.
    Local users who have been granted the privileges necessary to
    mount a filesystem would be able to craft a filesystem with a
    corrupted catalog name length, resulting in a system oops or
    memory corruption.
CVE-2008-5029
    Andrea Bittau reported a DoS issue in the unix socket subsystem
    that allows a local user to cause memory corruption, resulting in
    a kernel panic.
CVE-2008-5079
    Hugo Dias reported a DoS condition in the ATM subsystem that can
    be triggered by a local user by calling the svc_listen function
    twice on the same socket and reading /proc/net/atm/*vc.
CVE-2008-5182
    Al Viro reported race conditions in the inotify subsystem that may
    allow local users to acquire elevated privileges.
CVE-2008-5300
    Dann Frazier reported a DoS condition that allows local users to
    cause the out of memory handler to kill off privileged processes
    or trigger soft lockups due to a starvation issue in the unix
    socket subsystem.
For the stable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-23etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1687');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1687] DSA-1687-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1687-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '4.0', reference: '1.17+etch.23etch1');
deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-486', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-itanium', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-k7', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-prep', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-qemu', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-rpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-s390', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-s390x', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-486', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-itanium', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-k7', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-parisc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-prep', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-qemu', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-rpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-s390', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-s390x', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-image-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-support-2.6.18-6', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'user-mode-linux', release: '4.0', reference: '2.6.18-1um-2etch.23etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
deb_check(prefix: 'linux-2.6', release: '4.0', reference: '2.6.18.dfsg.1-23etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

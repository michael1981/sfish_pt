# This script was automatically generated from the dsa-1800
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38795);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1800");
 script_cve_id("CVE-2009-0028", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1046", "CVE-2009-1072", "CVE-2009-1184");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1800 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, privilege escalation or a sensitive
memory leak. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2009-0028
    Chris Evans discovered a situation in which a child process can
    send an arbitrary signal to its parent.
CVE-2009-0834
    Roland McGrath discovered an issue on amd64 kernels that allows
    local users to circumvent system call audit configurations which
    filter based on the syscall numbers or argument details.
CVE-2009-0835
    Roland McGrath discovered an issue on amd64 kernels with
    CONFIG_SECCOMP enabled. By making a specially crafted syscall,
    local users can bypass access restrictions.
CVE-2009-0859
    Jiri Olsa discovered that a local user can cause a denial of
    service (system hang) using a SHM_INFO shmctl call on kernels
    compiled with CONFIG_SHMEM disabled. This issue does not affect
    prebuilt Debian kernels.
CVE-2009-1046
    Mikulas Patocka reported an issue in the console subsystem that
    allows a local user to cause memory corruption by selecting a
    small number of 3-byte UTF-8 characters.
CVE-2009-1072
    Igor Zhbanov reported that nfsd was not properly dropping
    CAP_MKNOD, allowing users to create device nodes on file systems
    exported with root_squash.
CVE-2009-1184
    Dan Carpenter reported a coding issue in the selinux subsystem
    that allows local users to bypass certain networking checks when
    running with compat_net=1.
CVE-2009-1192
    Shaohua Li reported an issue in the AGP subsystem they may allow
    local users to read sensitive kernel memory due to a leak of
    uninitialized memory.
CVE-2009-1242
    Benjamin Gilbert reported a local denial of service vulnerability
    in the KVM VMX implementation that allows local users to trigger
    an oops.
CVE-2009-1265
    Thomas Pollet reported an overflow in the af_rose implementation
    that allows remote attackers to retrieve uninitialized kernel
    memory that may contain sensitive data.
CVE-2009-1337
    Oleg Nesterov discovered an issue in the exit_notify function that
    allows local users to send an arbitrary signal to a process by
    running a program that modifies the exit_signal field and then
    uses an exec system call to launch a setuid application.
CVE-2009-1338
    Daniel Hokka Zakrisson discovered that a kill(-1) is permitted to
    reach processes outside of the current process namespace.
CVE-2009-1439
    Pavan Naregundi reported an issue in the CIFS filesystem code that
    allows remote users to overwrite memory via a long
    nativeFileSystem field in a Tree Connect response during mount.
For the oldstable distribution (etch), these problems, where applicable,
will be fixed in future updates to linux-2.6 and linux-2.6.24.
For the stable distribution (lenny), these problems have been fixed in
version 2.6.26-15lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1800');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1800] DSA-1800-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1800-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'linux-doc-2.6.26', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-486', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-4kc-malta', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-5kc-malta', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-686-bigmem', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-alpha', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-arm', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-armel', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-hppa', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-i386', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-ia64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-mips', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-mipsel', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-powerpc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-s390', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-all-sparc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-alpha-generic', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-alpha-legacy', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-alpha-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-common', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-common-openvz', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-common-vserver', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-common-xen', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-footbridge', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-iop32x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-itanium', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-ixp4xx', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-mckinley', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-openvz-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-openvz-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-orion5x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc64-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-powerpc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-powerpc-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-powerpc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-r4k-ip22', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-r5k-cobalt', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-r5k-ip32', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-s390', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-s390x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-sb1-bcm91250a', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-sb1a-bcm91480b', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-sparc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-sparc64-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-versatile', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-686-bigmem', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-itanium', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-mckinley', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-powerpc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-powerpc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-s390x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-sparc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-headers-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-486', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-4kc-malta', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-5kc-malta', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-686-bigmem', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-alpha-legacy', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-alpha-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-footbridge', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-iop32x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-itanium', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-ixp4xx', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-mckinley', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-openvz-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-openvz-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-orion5x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-parisc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-parisc-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-parisc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-parisc64-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-powerpc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-powerpc-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-powerpc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-r4k-ip22', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-r5k-cobalt', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-r5k-ip32', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-s390', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-s390-tape', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-s390x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-sb1-bcm91250a', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-sb1a-bcm91480b', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-sparc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-sparc64-smp', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-versatile', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-686-bigmem', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-itanium', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-mckinley', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-powerpc', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-powerpc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-s390x', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-sparc64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-image-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-libc-dev', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-manual-2.6.26', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-modules-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-modules-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-patch-debian-2.6.26', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-source-2.6.26', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-support-2.6.26-2', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-tree-2.6.26', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'user-mode-linux', release: '5.0', reference: '2.6.26-1um-2+15lenny2');
deb_check(prefix: 'xen-linux-system-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'xen-linux-system-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny2');
deb_check(prefix: 'linux-2.6', release: '5.0', reference: '2.6.26-15lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-1749
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35987);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1749");
 script_cve_id("CVE-2009-0029", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1749 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2009-0029
    Christian Borntraeger discovered an issue effecting the alpha,
    mips, powerpc, s390 and sparc64 architectures that allows local
    users to cause a denial of service or potentially gain elevated
    privileges.
CVE-2009-0031
    Vegard Nossum discovered a memory leak in the keyctl subsystem
    that allows local users to cause a denial of service by consuming
    all of kernel memory.
CVE-2009-0065
    Wei Yongjun discovered a memory overflow in the SCTP
    implementation that can be triggered by remote users.
CVE-2009-0269
    Duane Griffin provided a fix for an issue in the eCryptfs
    subsystem which allows local users to cause a denial of service
    (fault or memory corruption).
CVE-2009-0322
    Pavel Roskin provided a fix for an issue in the dell_rbu driver
    that allows a local user to cause a denial of service (oops) by
    reading 0 bytes from a sysfs entry.
CVE-2009-0676
    Clement LECIGNE discovered a bug in the sock_getsockopt function
    that may result in leaking sensitive kernel memory.
CVE-2009-0675
    Roel Kluin discovered inverted logic in the skfddi driver that
    permits local, unprivileged users to reset the driver statistics.
CVE-2009-0745
    Peter Kerwien discovered an issue in the ext4 filesystem that
    allows local users to cause a denial of service (kernel oops)
    during a resize operation.
CVE-2009-0746
    Sami Liedes reported an issue in the ext4 filesystem that allows
    local users to cause a denial of service (kernel oops) when
    accessing a specially crafted corrupt filesystem.
CVE-2009-0747
    David Maciejak reported an issue in the ext4 filesystem that
    allows local users to cause a denial of service (kernel oops) when
    mounting a specially crafted corrupt filesystem.
CVE-2009-0748
    David Maciejak reported an additional issue in the ext4 filesystem
    that allows local users to cause a denial of service (kernel oops)
    when mounting a specially crafted corrupt filesystem.
For the oldstable distribution (etch), these problems, where applicable,
will be fixed in future updates to linux-2.6 and linux-2.6.24.
For the stable distribution (lenny), these problems have been fixed in
version 2.6.26-13lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1749');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1749] DSA-1749-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1749-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'linux-doc-2.6.26', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-486', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-4kc-malta', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-5kc-malta', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-686-bigmem', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-alpha', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-arm', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-armel', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-hppa', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-i386', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-ia64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-mips', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-mipsel', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-powerpc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-s390', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-all-sparc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-alpha-generic', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-alpha-legacy', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-alpha-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-common', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-common-openvz', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-common-vserver', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-common-xen', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-footbridge', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-iop32x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-itanium', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-ixp4xx', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-mckinley', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-openvz-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-openvz-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-orion5x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-parisc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-parisc-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-parisc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-parisc64-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-powerpc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-powerpc-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-powerpc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-r4k-ip22', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-r5k-cobalt', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-r5k-ip32', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-s390', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-s390x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-sb1-bcm91250a', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-sb1a-bcm91480b', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-sparc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-sparc64-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-versatile', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-686-bigmem', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-itanium', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-mckinley', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-powerpc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-powerpc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-s390x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-vserver-sparc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-xen-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-headers-2.6.26-1-xen-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-486', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-4kc-malta', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-5kc-malta', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-686-bigmem', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-alpha-generic', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-alpha-legacy', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-alpha-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-footbridge', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-iop32x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-itanium', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-ixp4xx', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-mckinley', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-openvz-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-openvz-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-orion5x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-parisc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-parisc-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-parisc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-parisc64-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-powerpc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-powerpc-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-powerpc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-r4k-ip22', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-r5k-cobalt', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-r5k-ip32', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-s390', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-s390-tape', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-s390x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-sb1-bcm91250a', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-sb1a-bcm91480b', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-sparc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-sparc64-smp', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-versatile', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-686-bigmem', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-itanium', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-mckinley', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-powerpc', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-powerpc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-s390x', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-vserver-sparc64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-xen-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-image-2.6.26-1-xen-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-libc-dev', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-manual-2.6.26', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-modules-2.6.26-1-xen-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-modules-2.6.26-1-xen-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-patch-debian-2.6.26', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-source-2.6.26', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-support-2.6.26-1', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-tree-2.6.26', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'xen-linux-system-2.6.26-1-xen-686', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'xen-linux-system-2.6.26-1-xen-amd64', release: '5.0', reference: '2.6.26-13lenny2');
deb_check(prefix: 'linux-2.6', release: '5.0', reference: '2.6.26-13lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

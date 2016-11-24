# This script was automatically generated from the dsa-1289
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25226);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1289");
 script_cve_id("CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1289 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-1496
    Michal Miroslaw reported a DoS vulnerability (crash) in netfilter.
    A remote attacker can cause a NULL pointer dereference in the
    nfnetlink_log function.
CVE-2007-1497
    Patrick McHardy reported an vulnerability in netfilter that may
    allow attackers to bypass certain firewall rules. The nfctinfo
    value of reassembled IPv6 packet fragments were incorrectly initialized
    to 0 which allowed these packets to become tracked as ESTABLISHED.
CVE-2007-1861
    Jaco Kroon reported a bug in which NETLINK_FIB_LOOKUP packages were
    incorrectly routed back to the kernel resulting in an infinite
    recursion condition. Local users can exploit this behavior
    to cause a DoS (crash).
For the stable distribution (etch) these problems have been fixed in version 
2.6.18.dfsg.1-12etch2.
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1289');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1289] DSA-1289-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1289-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '4.0', reference: '1.17+etch2');
deb_check(prefix: 'kernel-patch-openvz', release: '4.0', reference: '028.18.1etch1');
deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-486', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-itanium', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-prep', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-qemu', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-rpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-s390', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-xen', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-486', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-itanium', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-parisc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-prep', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-qemu', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-rpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-s390', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-image-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-support-2.6.18-4', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'user-mode-linux', release: '4.0', reference: '2.6.18-1um-2etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
deb_check(prefix: 'linux-2.6', release: '4.0', reference: '2.6.18.dfsg.1-12etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

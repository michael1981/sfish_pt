# This script was automatically generated from the dsa-1428
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29263);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1428");
 script_cve_id("CVE-2007-3104", "CVE-2007-4997", "CVE-2007-5500", "CVE-2007-5904");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1428 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
This is an update to DSA 1428-1 which omitted a reference to CVE-2007-5904.
CVE-2007-3104
    Eric Sandeen provided a backport of Tejun Heo\'s fix for a local denial
    of service vulnerability in sysfs. Under memory pressure, a dentry
    structure maybe reclaimed resulting in a bad pointer dereference causing
    an oops during a readdir.
CVE-2007-4997
    Chris Evans discovered an issue with certain drivers that make use of the
    Linux kernel\'s ieee80211 layer. A remote user could generate a malicious
    802.11 frame that could result in a denial of service (crash). The ipw2100
    driver is known to be affected by this issue, while the ipw2200 is
    believed not to be.
CVE-2007-5500
    Scott James Remnant diagnosed a coding error in the implementation of
    ptrace which could be used by a local user to cause the kernel to enter
    an infinite loop.
CVE-2007-5904
    Przemyslaw Wegrzyn discovered an issue in the CIFS filesystem that could
    allow a malicious server to cause a denial of service (crash) by overflowing
    a buffer.
These problems have been fixed in the stable distribution in version 
2.6.18.dfsg.1-13etch5.
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1428');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1428] DSA-1428-2 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1428-2 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '4.0', reference: '1.17+etch.13etch5');
deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-486', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-itanium', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-prep', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-qemu', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-rpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-xen', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-486', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-itanium', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-parisc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-prep', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-qemu', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-rpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-image-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-support-2.6.18-5', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'user-mode-linux', release: '4.0', reference: '2.6.18-1um-2etch.13etch5');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

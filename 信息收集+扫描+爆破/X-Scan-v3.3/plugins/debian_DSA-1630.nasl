# This script was automatically generated from the dsa-1630
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34032);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1630");
 script_cve_id("CVE-2007-6282", "CVE-2008-0598", "CVE-2008-2729", "CVE-2008-2812", "CVE-2008-2826", "CVE-2008-2931", "CVE-2008-3272");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1630 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that may
lead to a denial of service or arbitrary code execution. The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2007-6282
    Dirk Nehring discovered a vulnerability in the IPsec code that allows
    remote users to cause a denial of service by sending a specially crafted
    ESP packet.
CVE-2008-0598
    Tavis Ormandy discovered a vulnerability that allows local users to access
    uninitialized kernel memory, possibly leaking sensitive data. This issue
    is specific to the amd64-flavour kernel images.
CVE-2008-2729
    Andi Kleen discovered an issue where uninitialized kernel memory
    was being leaked to userspace during an exception. This issue may allow
    local users to gain access to sensitive data. Only the amd64-flavour
    Debian kernel images are affected.
CVE-2008-2812
    Alan Cox discovered an issue in multiple tty drivers that allows
    local users to trigger a denial of service (NULL pointer dereference)
    and possibly obtain elevated privileges.
CVE-2008-2826
    Gabriel Campana discovered an integer overflow in the sctp code that
    can be exploited by local users to cause a denial of service.
CVE-2008-2931
    Miklos Szeredi reported a missing privilege check in the do_change_type()
    function. This allows local, unprivileged users to change the properties
    of mount points.
CVE-2008-3272
    Tobias Klein reported a locally exploitable data leak in the
    snd_seq_oss_synth_make_info() function. This may allow local users
    to gain access to sensitive information.
CVE-2008-3275
    Zoltan Sogor discovered a coding error in the VFS that allows local users
    to exploit a kernel memory leak resulting in a denial of service.
For the stable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-22etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1630');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1630] DSA-1630-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1630-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '4.0', reference: '1.17+etch.22etch2');
deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-486', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-itanium', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-k7', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-prep', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-qemu', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-rpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-s390', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-s390x', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-headers-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-486', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-itanium', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-k7', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-parisc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-prep', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-qemu', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-rpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-s390', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-s390x', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-image-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-modules-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-support-2.6.18-6', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'user-mode-linux', release: '4.0', reference: '2.6.18-1um-2etch.22etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-6-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
deb_check(prefix: 'linux-2.6', release: '4.0', reference: '2.6.18.dfsg.1-22etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

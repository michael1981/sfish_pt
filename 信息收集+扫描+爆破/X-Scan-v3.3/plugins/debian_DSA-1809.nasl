# This script was automatically generated from the dsa-1809
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38990);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1809");
 script_cve_id("CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1809 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2009-1630
    Frank Filz discovered that local users may be able to execute
    files without execute permission when accessed via an nfs4 mount.
CVE-2009-1633
    Jeff Layton and Suresh Jayaraman fixed several buffer overflows in
    the CIFS filesystem which allow remote servers to cause memory
    corruption.
CVE-2009-1758
    Jan Beulich discovered an issue in Xen where local guest users may
    cause a denial of service (oops).
This update also fixes a regression introduced by the fix for
CVE-2009-1184 
in 2.6.26-15lenny3. This prevents a boot time panic on systems with SELinux
enabled.
For the oldstable distribution (etch), these problems, where
applicable, will be fixed in future updates to linux-2.6 and
linux-2.6.24.
For the stable distribution (lenny), these problems have been fixed in
version 2.6.26-15lenny3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1809');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1809] DSA-1809-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1809-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'linux-doc-2.6.26', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-486', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-4kc-malta', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-5kc-malta', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-686-bigmem', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-alpha', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-arm', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-armel', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-hppa', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-i386', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-ia64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-mips', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-mipsel', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-powerpc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-s390', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-all-sparc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-alpha-generic', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-alpha-legacy', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-alpha-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-common', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-common-openvz', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-common-vserver', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-common-xen', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-footbridge', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-iop32x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-itanium', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-ixp4xx', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-mckinley', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-openvz-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-openvz-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-orion5x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-parisc64-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-powerpc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-powerpc-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-powerpc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-r4k-ip22', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-r5k-cobalt', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-r5k-ip32', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-s390', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-s390x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-sb1-bcm91250a', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-sb1a-bcm91480b', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-sparc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-sparc64-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-versatile', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-686-bigmem', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-itanium', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-mckinley', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-powerpc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-powerpc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-s390x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-vserver-sparc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-headers-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-486', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-4kc-malta', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-5kc-malta', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-686-bigmem', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-alpha-generic', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-alpha-legacy', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-alpha-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-footbridge', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-iop32x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-itanium', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-ixp4xx', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-mckinley', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-openvz-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-openvz-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-orion5x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-parisc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-parisc-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-parisc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-parisc64-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-powerpc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-powerpc-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-powerpc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-r4k-ip22', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-r5k-cobalt', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-r5k-ip32', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-s390', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-s390-tape', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-s390x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-sb1-bcm91250a', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-sb1a-bcm91480b', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-sparc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-sparc64-smp', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-versatile', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-686-bigmem', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-itanium', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-mckinley', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-powerpc', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-powerpc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-s390x', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-vserver-sparc64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-image-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-libc-dev', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-manual-2.6.26', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-modules-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-modules-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-patch-debian-2.6.26', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-source-2.6.26', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-support-2.6.26-2', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-tree-2.6.26', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'user-mode-linux', release: '5.0', reference: '2.6.26-1um-2+15lenny3');
deb_check(prefix: 'xen-linux-system-2.6.26-2-xen-686', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'xen-linux-system-2.6.26-2-xen-amd64', release: '5.0', reference: '2.6.26-15lenny3');
deb_check(prefix: 'linux-2.6', release: '5.0', reference: '2.6.26-15lenny3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

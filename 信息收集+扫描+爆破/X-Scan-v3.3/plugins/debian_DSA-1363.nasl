# This script was automatically generated from the dsa-1363
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25963);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1363");
 script_cve_id("CVE-2007-2172", "CVE-2007-2875", "CVE-2007-3105", "CVE-2007-3843");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1363 security update');
 script_set_attribute(attribute: 'description', value:
'                 
Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-2172
    Thomas Graf reported a typo in the IPv4 protocol handler that could
    be used by a local attacker to overrun an array via crafted packets,
    potentially resulting in a Denial of Service (system crash).
    The DECnet counterpart of this issue was already fixed in DSA-1356.
CVE-2007-2875
    iDefense reported a potential integer underflow in the cpuset filesystem
    which may permit local attackers to gain access to sensitive kernel
    memory. This vulnerability is only exploitable if the cpuset filesystem
    is mounted.
CVE-2007-3105
    The PaX Team discovered a potential buffer overflow in the random number
    generator which may permit local users to cause a denial of service or
    gain additional privileges. This issue is not believed to effect default
    Debian installations where only root has sufficient privileges to exploit
    it.
CVE-2007-3843
    A coding error in the CIFS subsystem permits the use of unsigned messages
    even if the client has configured the system to enforce
    signing by passing the sec=ntlmv2i mount option. This may allow remote
    attackers to spoof CIFS network traffic.
CVE-2007-4308
    Alan Cox reported an issue in the aacraid driver that allows unprivileged
    local users to make ioctl calls which should be restricted to admin
    privileges.
These problems have been fixed in the stable distribution in version 
2.6.18.dfsg.1-13etch2.
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1363');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1363] DSA-1363-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1363-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-486', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-itanium', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-prep', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-qemu', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-rpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-xen', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-486', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-itanium', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-parisc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-prep', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-qemu', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-rpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-image-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-support-2.6.18-5', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

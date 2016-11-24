# This script was automatically generated from the dsa-1286
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25153);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1286");
 script_cve_id("CVE-2007-0005", "CVE-2007-0958", "CVE-2007-1357", "CVE-2007-1592");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1286 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-0005
    Daniel Roethlisberger discovered two buffer overflows in the cm4040
    driver for the Omnikey CardMan 4040 device. A local user or malicious
    device could exploit this to execute arbitrary code in kernel space.
CVE-2007-0958
    Santosh Eraniose reported a vulnerability that allows local users to read
    otherwise unreadable files by triggering a core dump while using PT_INTERP.
    This is related to CVE-2004-1073.
CVE-2007-1357
    Jean Delvare reported a vulnerability in the appletalk subsystem.
    Systems with the appletalk module loaded can be triggered to crash
    by other systems on the local network via a malformed frame.
CVE-2007-1592
    Masayuki Nakagawa discovered that flow labels were inadvertently
    being shared between listening sockets and child sockets. This defect
    can be exploited by local users to cause a DoS (Oops).
This problem has been fixed in the stable distribution in version 
2.6.18.dfsg.1-12etch1.
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1286');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1286] DSA-1286-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1286-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '4.0', reference: '1.17etch1');
deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-486', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-itanium', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-prep', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-rpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-s390', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-xen', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-headers-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-486', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-itanium', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-parisc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-prep', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-rpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-s390', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-image-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-modules-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-support-2.6.18-4', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'user-mode-linux', release: '4.0', reference: '2.6.18-1um-2etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-4-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-12etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

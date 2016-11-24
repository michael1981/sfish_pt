# This script was automatically generated from the dsa-1356
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25909);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1356");
 script_cve_id("CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3513", "CVE-2007-3642");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1356 security update');
 script_set_attribute(attribute: 'description', value:
'                 
Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-1353
    Ilja van Sprundel discovered that kernel memory could be leaked via the
    Bluetooth setsockopt call due to an uninitialized stack buffer. This
    could be used by local attackers to read the contents of sensitive kernel
    memory.
CVE-2007-2172
    Thomas Graf reported a typo in the DECnet protocol handler that could
    be used by a local attacker to overrun an array via crafted packets,
    potentially resulting in a Denial of Service (system crash).
    A similar issue exists in the IPV4 protocol handler and will be fixed
    in a subsequent update.
CVE-2007-2453
    A couple of issues with random number generation were discovered.
    Slightly less random numbers resulted from hashing a subset of the
    available entropy. Zero-entropy systems were seeded with the same
    inputs at boot time, resulting in repeatable series of random numbers.
CVE-2007-2525
    Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused
    by releasing a socket before PPPIOCGCHAN is called upon it. This could
    be used by a local user to DoS a system by consuming all available memory.
CVE-2007-2876
    Vilmos Nebehaj discovered a NULL pointer dereference condition in the
    netfilter subsystem. This allows remote systems which communicate using
    the SCTP protocol to crash a system by creating a connection with an
    unknown chunk type.
CVE-2007-3513
    Oliver Neukum reported an issue in the usblcd driver which, by not
    limiting the size of write buffers, permits local users with write access
    to trigger a DoS by consuming all available memory.
CVE-2007-3642
    Zhongling Wen reported an issue in nf_conntrack_h323 where the lack of
    range checking may lead to NULL pointer dereferences. Remote attackers
    could exploit this to create a DoS condition (system crash).
CVE-2007-3848
    Wojciech Purczynski discovered that pdeath_signal was not being reset
    properly under certain conditions which may allow local users to gain
    privileges by sending arbitrary signals to suid binaries.
CVE-2007-3851
    Dave Airlie reported that Intel 965 and above chipsets have relocated
    their batch buffer security bits. Local X server users may exploit this
    to write user data to arbitrary physical memory addresses.
These problems have been fixed in the stable distribution in version 
2.6.18.dfsg.1-13etch1.
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1356');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1356] DSA-1356-1 linux-2.6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1356-1 linux-2.6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'linux-doc-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-486', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-arm', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-hppa', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-i386', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-ia64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-mips', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-mipsel', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-all-sparc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-itanium', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-prep', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-qemu', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-rpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-xen', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-headers-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-486', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-686-bigmem', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-generic', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-legacy', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-alpha-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-footbridge', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-iop32x', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-itanium', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-ixp4xx', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-mckinley', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-parisc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-parisc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-parisc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-parisc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc-miboot', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-prep', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-qemu', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-r3k-kn02', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-r4k-ip22', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-r4k-kn04', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-r5k-cobalt', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-r5k-ip32', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-rpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-s390', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-s390-tape', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-s3c2410', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-sb1-bcm91250a', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-sb1a-bcm91480b', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-sparc32', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-sparc64-smp', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-alpha', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-k7', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-powerpc', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-powerpc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-s390x', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-vserver-sparc64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-image-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-manual-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-modules-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-patch-debian-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-source-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-support-2.6.18-5', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'linux-tree-2.6.18', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-vserver-686', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
deb_check(prefix: 'xen-linux-system-2.6.18-5-xen-vserver-amd64', release: '4.0', reference: '2.6.18.dfsg.1-13etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

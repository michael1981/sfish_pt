# This script was automatically generated from the dsa-1017
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22559);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1017");
 script_cve_id("CVE-2004-1017", "CVE-2005-0124", "CVE-2005-0449", "CVE-2005-2457", "CVE-2005-2490", "CVE-2005-2555", "CVE-2005-2709");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1017 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2004-1017
    Multiple overflows exist in the io_edgeport driver which might be usable
    as a denial of service attack vector.
CVE-2005-0124
    Bryan Fulton reported a bounds checking bug in the coda_pioctl function
    which may allow local users to execute arbitrary code or trigger a denial
    of service attack.
CVE-2005-0449
    An error in the skb_checksum_help() function from the netfilter framework
    has been discovered that allows the bypass of packet filter rules or
    a denial of service attack.
CVE-2005-2457
    Tim Yamin discovered that insufficient input validation in the zisofs driver
    for compressed ISO file systems allows a denial of service attack through
    maliciously crafted ISO images.
CVE-2005-2490
    A buffer overflow in the sendmsg() function allows local users to execute
    arbitrary code.
CVE-2005-2555
    Herbert Xu discovered that the setsockopt() function was not restricted to
    users/processes with the CAP_NET_ADMIN capability. This allows attackers to
    manipulate IPSEC policies or initiate a denial of service attack. 
CVE-2005-2709
    Al Viro discovered a race condition in the /proc handling of network devices.
    A (local) attacker could exploit the stale reference after interface shutdown
    to cause a denial of service or possibly execute code in kernel mode.
CVE-2005-2800
    Jan Blunck discovered that repeated failed reads of /proc/scsi/sg/devices
    leak memory, which allows a denial of service attack.
CVE-2005-2973
    Tetsuo Handa discovered that the udp_v6_get_port() function from the IPv6 code
    can be forced into an endless loop, which allows a denial of service attack.
CVE-2005-3044
    Vasiliy Averin discovered that the reference counters from sockfd_put() and 
    fput() can be forced into overlapping, which allows a denial of service attack
    through a null pointer dereference.
CVE-2005-3053
    Eric Dumazet discovered that the set_mempolicy() system call accepts a negative
    value for its first argument, which triggers a BUG() assert. This allows a
    denial of service attack.
CVE-2005-3055
    Harald Welte discovered that if a process issues a USB Request Block (URB)
    to a device and terminates before the URB completes, a stale pointer
    would be dereferenced.  This could be used to trigger a denial of service
    attack.
CVE-2005-3180
    Pavel Roskin discovered that the driver for Orinoco wireless cards clears
    its buffers insufficiently. This could leak sensitive information into
    user space.
CVE-2005-3181
    Robert Derr discovered that the audit subsystem uses an incorrect function to
    free memory, which allows a denial of service attack.
CVE-2005-3257
    Rudolf Polzer discovered that the kernel improperly restricts access to the
    KDSKBSENT ioctl, which can possibly lead to privilege escalation.
CVE-2005-3356
    Doug Chapman discovered that the mq_open syscall can be tricked into
    de
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1017');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1017] DSA-1017-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1017-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-386', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-586tsc', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-686', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-686-smp', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-k6', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-k7', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.4.27-3-k7-smp', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.6.8-3-386', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.6.8-3-686', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.6.8-3-686-smp', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.6.8-3-k7', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'hostap-modules-2.6.8-3-k7-smp', release: '3.1', reference: '0.3.7-1sarge1');
deb_check(prefix: 'kernel-build-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-build-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-build-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-build-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-build-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-build-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-build-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-build-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-build-2.6.8-power3', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power3-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power4', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power4-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-powerpc', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-headers-2.4', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-headers-2.6', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-headers-2.6-32', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-headers-2.6-32-smp', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-headers-2.6-386', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-64', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-headers-2.6-64-smp', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-headers-2.6-686', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-686-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-amd64-generic', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-headers-2.6-amd64-k8', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-headers-2.6-amd64-k8-smp', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-headers-2.6-em64t-p4', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-headers-2.6-em64t-p4-smp', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-headers-2.6-generic', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6-k7', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-k7-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-sparc32', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-sparc64', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6-sparc64-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.6.8', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-generic', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-k8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-em64t-p4', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-12', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-32', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-32-smp', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-386', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-64', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-64-smp', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-686', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-686-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-generic', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-itanium', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-k7', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-k7-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-mckinley', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-sparc32', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-sparc64', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-2-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-image-2.4-powerpc', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.4-powerpc-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-32', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-image-2.6-32-smp', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-image-2.6-386', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-64', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-image-2.6-64-smp', release: '3.1', reference: '2.6.8-1sarge1');
deb_check(prefix: 'kernel-image-2.6-686', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-686-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-amd64-generic', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-image-2.6-amd64-k8', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-image-2.6-amd64-k8-smp', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-image-2.6-em64t-p4', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-image-2.6-em64t-p4-smp', release: '3.1', reference: '103sarge1');
deb_check(prefix: 'kernel-image-2.6-generic', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6-k7', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-k7-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6-power3', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-power3-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-power4', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-power4-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-powerpc', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-powerpc-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-2.6-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-sparc32', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-sparc64', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6-sparc64-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-amd64-generic', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-amd64-k8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-em64t-p4', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-2-32', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-32-smp', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-386', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-64', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-64-smp', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-686', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-686-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-generic', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-itanium', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-k7', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-k7-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-mckinley', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-s390', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-s390-tape', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-s390x', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-sparc32', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-sparc64', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-2-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-s390', release: '3.1', reference: '2.6.8-5sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-s390-tape', release: '3.1', reference: '2.6.8-5sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-s390x', release: '3.1', reference: '2.6.8-5sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-image-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge2');
deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-power3', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power3-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power4', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power4-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-powerpc', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge2');
deb_check(prefix: 'kernel-image-power3', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-power3-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-power4', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-power4-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-powerpc', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-image-powerpc-smp', release: '3.1', reference: '102sarge1');
deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge2');
deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge2');
deb_check(prefix: 'mol-modules-2.6.8-3-powerpc', release: '3.1', reference: '0.9.70+2.6.8+12sarge1');
deb_check(prefix: 'mol-modules-2.6.8-3-powerpc-smp', release: '3.1', reference: '0.9.70+2.6.8+12sarge1');
deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-386', release: '3.1', reference: '1.1-2sarge1');
deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-686', release: '3.1', reference: '1.1-2sarge1');
deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-686-smp', release: '3.1', reference: '1.1-2sarge1');
deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-k7', release: '3.1', reference: '1.1-2sarge1');
deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-k7-smp', release: '3.1', reference: '1.1-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

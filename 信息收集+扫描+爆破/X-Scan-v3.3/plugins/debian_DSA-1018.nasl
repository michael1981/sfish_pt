# This script was automatically generated from the dsa-1018
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22560);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1018");
 script_cve_id("CVE-2004-0887", "CVE-2004-1058", "CVE-2004-2607", "CVE-2005-0449", "CVE-2005-1761", "CVE-2005-2457", "CVE-2005-2555");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1018 security update');
 script_set_attribute(attribute: 'description', value:
' The original update lacked recompiled ALSA modules against the new kernel
ABI. Furthermore, kernel-latest-2.4-sparc now correctly depends on the
updated packages. For completeness we\'re providing the original problem description:

Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2004-0887
    Martin Schwidefsky discovered that the privileged instruction SACF (Set
    Address Space Control Fast) on the S/390 platform is not handled properly, 
    allowing for a local user to gain root privileges.
CVE-2004-1058
    A race condition allows for a local user to read the environment variables
    of another process that is still spawning through /proc/.../cmdline.
CVE-2004-2607
    A numeric casting discrepancy in sdla_xfer allows local users to read
    portions of kernel memory via a large len argument which is received as an
    int but cast to a short, preventing read loop from filling a buffer.
CVE-2005-0449
    An error in the skb_checksum_help() function from the netfilter framework
    has been discovered that allows the bypass of packet filter rules or
    a denial of service attack.
CVE-2005-1761
    A vulnerability in the ptrace subsystem of the IA-64 architecture can 
    allow local attackers to overwrite kernel memory and crash the kernel.
CVE-2005-2457
    Tim Yamin discovered that insufficient input validation in the compressed
    ISO file system (zisofs) allows a denial of service attack through
    maliciously crafted ISO images.
CVE-2005-2555
    Herbert Xu discovered that the setsockopt() function was not restricted to
    users/processes with the CAP_NET_ADMIN capability. This allows attackers to
    manipulate IPSEC policies or initiate a denial of service attack.
CVE-2005-2709
    Al Viro discovered a race condition in the /proc handling of network devices.
    A (local) attacker could exploit the stale reference after interface shutdown
    to cause a denial of service or possibly execute code in kernel mode.
CVE-2005-2973
    Tetsuo Handa discovered that the udp_v6_get_port() function from the IPv6 code
    can be forced into an endless loop, which allows a denial of service attack.
CVE-2005-3257
    Rudolf Polzer discovered that the kernel improperly restricts access to the
    KDSKBSENT ioctl, which can possibly lead to privilege escalation.
CVE-2005-3783
    The ptrace code using CLONE_THREAD didn\'t use the thread group ID to
    determine whether the caller is attaching to itself, which allows a denial
    of service attack.
CVE-2005-3806
    Yen Zheng discovered that the IPv6 flow label code modified an incorrect variable,
    which could lead to memory corruption and denial of service.
CVE-2005-3848
    Ollie Wild discovered a memory leak in the icmp_push_reply() function, which
    allows denial of service through memory consumption.
CVE-2005-3857
    Chris Wright discovered that excessive allocation of broken file lock leases
    in the VFS layer can exhaust memory and fill up the system logging, which
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1018');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1018] DSA-1018-2 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1018-2 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'i2c-2.4.27-3-386', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-2.4.27-3-586tsc', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-2.4.27-3-686', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-2.4.27-3-686-smp', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-2.4.27-3-k6', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-2.4.27-3-k7', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-2.4.27-3-k7-smp', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'i2c-source', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-build-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge1');
deb_check(prefix: 'kernel-headers-2.4-386', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-586tsc', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-686', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-686-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-generic', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-k6', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-k7', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-k7-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-s390', release: '3.1', reference: '2.4.27-1sarge1');
deb_check(prefix: 'kernel-headers-2.4-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-headers-2.4-sparc32', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-headers-2.4-sparc32-smp', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-headers-2.4-sparc64', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-headers-2.4-sparc64-smp', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-headers-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-headers-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge1');
deb_check(prefix: 'kernel-image-2.4-386', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-586tsc', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-686', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-686-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-generic', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4-k6', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-k7', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-k7-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4-s390', release: '3.1', reference: '2.4.27-1sarge1');
deb_check(prefix: 'kernel-image-2.4-s390x', release: '3.1', reference: '2.4.27-1sarge1');
deb_check(prefix: 'kernel-image-2.4-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-image-2.4-sparc32', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-image-2.4-sparc32-smp', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-image-2.4-sparc64', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-image-2.4-sparc64-smp', release: '3.1', reference: '42sarge1');
deb_check(prefix: 'kernel-image-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-s390', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-s390-tape', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-s390x', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge2');
deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge2');
deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge2');
deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge1');
deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'kernel-patch-2.4-i2c', release: '3.1', reference: '2.9.1-1sarge1');
deb_check(prefix: 'kernel-patch-2.4-lm-sensors', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-386', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-586tsc', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-686', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-686-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-k6', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-k7', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-k7-smp', release: '3.1', reference: '101sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge2');
deb_check(prefix: 'libsensors-dev', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'libsensors3', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-386', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-586tsc', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-686', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-686-smp', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-k6', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-k7', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-2.4.27-3-k7-smp', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'lm-sensors-source', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge2.040815-1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '3.2.5+2sarge1');
deb_check(prefix: 'sensord', release: '3.1', reference: '2.9.1-1sarge3');
deb_check(prefix: 'systemimager-boot-i386-standard', release: '3.1', reference: '3.2.3-6sarge1');
deb_check(prefix: 'systemimager-boot-ia64-standard', release: '3.1', reference: '3.2.3-6sarge1');
deb_check(prefix: 'systemimager-client', release: '3.1', reference: '3.2.3-6sarge1');
deb_check(prefix: 'systemimager-common', release: '3.1', reference: '3.2.3-6sarge1');
deb_check(prefix: 'systemimager-doc', release: '3.1', reference: '3.2.3-6sarge1');
deb_check(prefix: 'systemimager-server', release: '3.1', reference: '3.2.3-6sarge1');
deb_check(prefix: 'systemimager-server-flamethrowerd', release: '3.1', reference: '3.2.3-6sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

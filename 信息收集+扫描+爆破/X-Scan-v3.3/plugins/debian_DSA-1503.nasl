# This script was automatically generated from the dsa-1503
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31147);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1503");
 script_cve_id("CVE-2004-2731", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6106");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1503 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code.  The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2004-2731
    infamous41md reported multiple integer overflows in the Sbus PROM
    driver that would allow for a DoS (Denial of Service) attack by a
    local user, and possibly the execution of arbitrary code.
CVE-2006-4814
    Doug Chapman discovered a potential local DoS (deadlock) in the mincore
    function caused by improper lock handling.
CVE-2006-5753
    Eric Sandeen provided a fix for a local memory corruption vulnerability
    resulting from a misinterpretation of return values when operating on
    inodes which have been marked bad.
CVE-2006-5823
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted cramfs filesystem.
CVE-2006-6053
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted ext3 filesystem.
CVE-2006-6054
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted ext2 filesystem.
CVE-2006-6106
    Marcel Holtman discovered multiple buffer overflows in the Bluetooth
    subsystem which can be used to trigger a remote DoS (crash) and potentially
    execute arbitrary code.
CVE-2007-1353
    Ilja van Sprundel discovered that kernel memory could be leaked via the
    Bluetooth setsockopt call due to an uninitialized stack buffer. This
    could be used by local attackers to read the contents of sensitive kernel
    memory.
CVE-2007-1592
    Masayuki Nakagawa discovered that flow labels were inadvertently
    being shared between listening sockets and child sockets. This defect
    can be exploited by local users to cause a DoS (Oops).
CVE-2007-2172
    Thomas Graf reported a typo in the DECnet protocol handler that could
    be used by a local attacker to overrun an array via crafted packets,
    potentially resulting in a Denial of Service (system crash).
    A similar issue exists in the IPV4 protocol handler and will be fixed
    in a subsequent update.
CVE-2007-2525
    Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused
    by releasing a socket before PPPIOCGCHAN is called upon it. This could
    be used by a local user to DoS a system by consuming all available memory.
CVE-2007-3848
    Wojciech Purczynski discovered that pdeath_signal was not being reset
    properly under certain conditions which may allow local users to gain
    privileges by sending arbitrary signals to suid binaries.
CVE-2007-4308
    Alan Cox reported an issue in the aacraid driver that allows unprivileged
    local users to make ioctl calls which should be restricted to admin
    privileges.
CVE-2007-4311
    PaX team discovered an issue in the random driver where a defect in the
    reseeding code leads to a reduction in entropy.
CVE-2007-5093
    Alex Smith discovered an issue with the pwc driver for certain webcam
    d
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1503');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1503] DSA-1503-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1503-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hostap-modules-2.4.27-4-386', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.4.27-4-586tsc', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.4.27-4-686', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.4.27-4-686-smp', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.4.27-4-k6', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.4.27-4-k7', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.4.27-4-k7-smp', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.6.8-4-386', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.6.8-4-686', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.6.8-4-686-smp', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.6.8-4-k7', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'hostap-modules-2.6.8-4-k7-smp', release: '3.1', reference: '0.3.7-1sarge3');
deb_check(prefix: 'i2c-2.4.27-4-386', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-2.4.27-4-586tsc', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-2.4.27-4-686', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-2.4.27-4-686-smp', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-2.4.27-4-k6', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-2.4.27-4-k7', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-2.4.27-4-k7-smp', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'i2c-source', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-build-2.4.27-4', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge5');
deb_check(prefix: 'kernel-headers-2.4-386', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-586tsc', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-686', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-686-smp', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-generic', release: '3.1', reference: '101sarge3');
deb_check(prefix: 'kernel-headers-2.4-k6', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-k7', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-k7-smp', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-headers-2.4-s390', release: '3.1', reference: '2.4.27-1sarge2');
deb_check(prefix: 'kernel-headers-2.4-smp', release: '3.1', reference: '101sarge3');
deb_check(prefix: 'kernel-headers-2.4-sparc32', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-headers-2.4-sparc32-smp', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-headers-2.4-sparc64', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-headers-2.4-sparc64-smp', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-headers-2.4.27-4', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-386', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-586tsc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-686', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-686-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-generic', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-itanium', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-k6', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-k7', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-k7-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-mckinley', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-sparc32', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-sparc64', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-4-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-headers-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge5');
deb_check(prefix: 'kernel-image-2.4-386', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-586tsc', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-686', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-686-smp', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-generic', release: '3.1', reference: '101sarge3');
deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4-k6', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-k7', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-k7-smp', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4-s390', release: '3.1', reference: '2.4.27-1sarge2');
deb_check(prefix: 'kernel-image-2.4-s390x', release: '3.1', reference: '2.4.27-1sarge2');
deb_check(prefix: 'kernel-image-2.4-smp', release: '3.1', reference: '101sarge3');
deb_check(prefix: 'kernel-image-2.4-sparc32', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-image-2.4-sparc32-smp', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-image-2.4-sparc64', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-image-2.4-sparc64-smp', release: '3.1', reference: '42sarge3');
deb_check(prefix: 'kernel-image-2.4.27-4-386', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-586tsc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-686', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-686-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-generic', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-itanium', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-k6', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-k7', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-k7-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-mckinley', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-s390', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-s390-tape', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-s390x', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-sparc32', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-sparc64', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-image-2.4.27-4-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge6');
deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge6');
deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge6');
deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge5');
deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'kernel-patch-2.4-i2c', release: '3.1', reference: '2.9.1-1sarge2');
deb_check(prefix: 'kernel-patch-2.4-lm-sensors', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-386', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-586tsc', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-686', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-686-smp', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-k6', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-k7', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4-k7-smp', release: '3.1', reference: '101sarge2');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-386', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-586tsc', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-686', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-686-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-k6', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-k7', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-4-k7-smp', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge6');
deb_check(prefix: 'libsensors-dev', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'libsensors3', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-386', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-586tsc', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-686', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-686-smp', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-k6', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-k7', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-2.4.27-4-k7-smp', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'lm-sensors-source', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge4.040815-3');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-386', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-586tsc', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-686', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-686-smp', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-k6', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-k7', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'pcmcia-modules-2.4.27-4-k7-smp', release: '3.1', reference: '3.2.5+2sarge2');
deb_check(prefix: 'sensord', release: '3.1', reference: '2.9.1-1sarge4');
deb_check(prefix: 'systemimager-boot-i386-standard', release: '3.1', reference: '3.2.3-6sarge5');
deb_check(prefix: 'systemimager-boot-ia64-standard', release: '3.1', reference: '3.2.3-6sarge5');
deb_check(prefix: 'systemimager-client', release: '3.1', reference: '3.2.3-6sarge5');
deb_check(prefix: 'systemimager-common', release: '3.1', reference: '3.2.3-6sarge5');
deb_check(prefix: 'systemimager-doc', release: '3.1', reference: '3.2.3-6sarge5');
deb_check(prefix: 'systemimager-server', release: '3.1', reference: '3.2.3-6sarge5');
deb_check(prefix: 'systemimager-server-flamethrowerd', release: '3.1', reference: '3.2.3-6sarge5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

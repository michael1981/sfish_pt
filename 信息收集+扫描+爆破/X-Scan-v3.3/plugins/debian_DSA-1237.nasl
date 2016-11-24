# This script was automatically generated from the dsa-1237
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23911);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1237");
 script_cve_id("CVE-2006-4093", "CVE-2006-4538", "CVE-2006-4997", "CVE-2006-5174", "CVE-2006-5871");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1237 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2005-4093
    Olof Johansson reported a local DoS (Denial of Service) vulnerability
    on the PPC970 platform. Unprivileged users can hang the system by
    executing the <q>attn</q> instruction, which was not being disabled at boot.
CVE-2006-4538
    Kirill Korotaev reported a local DoS (Denial of Service) vulnerability
    on the ia64 and sparc architectures. A user could cause the system to
    crash by executing a malformed ELF binary due to insufficient verification
    of the memory layout.
CVE-2006-4997
    ADLab Venustech Info Ltd reported a potential remote DoS (Denial of
    Service) vulnerability in the IP over ATM subsystem. A remote system
    could cause the system to crash by sending specially crafted packets
    that would trigger an attempt to free an already-freed pointer
    resulting in a system crash.
CVE-2006-5174
    Martin Schwidefsky reported a potential leak of sensitive information
    on s390 systems. The copy_from_user function did not clear the remaining
    bytes of the kernel buffer after receiving a fault on the userspace
    address, resulting in a leak of uninitialized kernel memory. A local user
    could exploit this by appending to a file from a bad address.
CVE-2006-5649
    Fabio Massimo Di Nitto reported a potential remote DoS (Denial of Service)
    vulnerability on powerpc systems.  The alignment exception only
    checked the exception table for -EFAULT, not for other errors. This can
    be exploited by a local user to cause a system crash (panic).
CVE-2006-5871
    Bill Allombert reported that various mount options are ignored by smbfs
    when UNIX extensions are enabled. This includes the uid, gid and mode
    options. Client systems would silently use the server-provided settings
    instead of honoring these options, changing the security model. This
    update includes a fix from Haroldo Gamal that forces the kernel to honor
    these mount options. Note that, since the current versions of smbmount
    always pass values for these options to the kernel, it is not currently
    possible to activate unix extensions by omitting mount options. However,
    this behavior is currently consistent with the current behavior of the
    next Debian release, \'etch\'.
The following matrix explains which kernel version for which architecture
fix the problems mentioned above:
The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1237');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1237] DSA-1237-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1237-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-build-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-build-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge4');
deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-headers-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-generic', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-itanium', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-mckinley', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc32', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc64', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-2-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-headers-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-headers-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge4');
deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-generic', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-itanium', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-mckinley', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-s390', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-s390-tape', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-s390x', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc32', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc64', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-2-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-image-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-s390', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-s390-tape', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-s390x', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge5');
deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge5');
deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge5');
deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge4');
deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge5');
deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge4.040815-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

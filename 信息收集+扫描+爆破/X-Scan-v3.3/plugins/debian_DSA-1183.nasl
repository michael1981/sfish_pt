# This script was automatically generated from the dsa-1183
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22725);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1183");
 script_cve_id("CVE-2005-4798", "CVE-2006-1528", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-3745", "CVE-2006-4535");
 script_bugtraq_id(18081, 18101, 18847, 19666, 20087);
 script_xref(name: "CERT", value: "681569");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1183 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in the Linux
kernel which may lead to a denial of service or even the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2005-4798
    A buffer overflow in NFS readlink handling allows a malicious
    remote server to cause a denial of service.
CVE-2006-2935
    Diego Calleja Garcia discovered a buffer overflow in the DVD
    handling code that could be exploited by a specially crafted DVD
    USB storage device to execute arbitrary code.
CVE-2006-1528
    A bug in the SCSI driver allows a local user to cause a denial of
    service.
CVE-2006-2444
    Patrick McHardy discovered a bug in the SNMP NAT helper that
    allows remote attackers to cause a denial of service.
CVE-2006-2446
    A race condition in the socket buffer handling allows remote
    attackers to cause a denial of service.
CVE-2006-3745
    Wei Wang discovered a bug in the SCTP implementation that allows
    local users to cause a denial of service and possibly gain root
    privileges.
CVE-2006-4535
    David Miller reported a problem with the fix for CVE-2006-3745
    that allows local users to crash the system via an SCTP
    socket with a certain SO_LINGER value.
The following matrix explains which kernel version for which
architecture fixes the problem mentioned above:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1183');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package and reboot the
machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1183] DSA-1183-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1183-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge4');
deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-build-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1');
deb_check(prefix: 'kernel-build-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge3');
deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
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
deb_check(prefix: 'kernel-headers-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-headers-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge3');
deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge4');
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
deb_check(prefix: 'kernel-image-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-s390', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-s390-tape', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-s390x', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-image-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge4');
deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge4');
deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge4');
deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge3');
deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-patch-2.4.27-s390', release: '3.1', reference: '2.4.27-2sarge1');
deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge4');
deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge3');
deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge4.040815-1');
deb_check(prefix: 'systemimager-boot-i386-standard', release: '3.1', reference: '3.2.3-6sarge3');
deb_check(prefix: 'systemimager-boot-ia64-standard', release: '3.1', reference: '3.2.3-6sarge3');
deb_check(prefix: 'systemimager-client', release: '3.1', reference: '3.2.3-6sarge3');
deb_check(prefix: 'systemimager-common', release: '3.1', reference: '3.2.3-6sarge3');
deb_check(prefix: 'systemimager-doc', release: '3.1', reference: '3.2.3-6sarge3');
deb_check(prefix: 'systemimager-server', release: '3.1', reference: '3.2.3-6sarge3');
deb_check(prefix: 'systemimager-server-flamethrowerd', release: '3.1', reference: '3.2.3-6sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

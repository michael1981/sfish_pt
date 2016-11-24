# This script was automatically generated from the dsa-1304
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25529);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1304");
 script_cve_id("CVE-2005-4811", "CVE-2006-4623", "CVE-2006-4814", "CVE-2006-5753");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1304 security update');
 script_set_attribute(attribute: 'description', value:
'                 CVE-2006-6060 CVE-2006-6106 CVE-2006-6535 CVE-2007-0958
                 CVE-2007-1357 CVE-2007-1592
Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. 
This update also fixes a regression in the smbfs subsystem which was introduced
in DSA-1233 which caused symlinks to be interpreted as regular files.
The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2005-4811
    David Gibson reported an issue in the hugepage code which could permit
    a local DoS (system crash) on appropriately configured systems.
CVE-2006-4814
    Doug Chapman discovered a potential local DoS (deadlock) in the mincore
    function caused by improper lock handling.
CVE-2006-4623
    Ang Way Chuang reported a remote DoS (crash) in the dvb driver which
    can be triggered by a ULE package with an SNDU length of 0.
CVE-2006-5753
    Eric Sandeen provided a fix for a local memory corruption vulnerability
    resulting from a misinterpretation of return values when operating on
    inodes which have been marked bad.
CVE-2006-5754
    Darrick Wong discovered a local DoS (crash) vulnerability resulting from
    the incorrect initialization of <q>nr_pages</q> in aio_setup_ring().
CVE-2006-5757
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted iso9660 filesystem.
CVE-2006-6053
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted ext3 filesystem.
CVE-2006-6056
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted hfs filesystem on
    systems with SELinux hooks enabled (Debian does not enable SELinux by
    default).
CVE-2006-6060
    LMH reported a potential local DoS (infinite loop) which could be exploited
    by a malicious user with the privileges to mount and read a corrupted NTFS
    filesystem.
CVE-2006-6106
    Marcel Holtman discovered multiple buffer overflows in the Bluetooth
    subsystem which can be used to trigger a remote DoS (crash) and potentially
    execute arbitrary code.
CVE-2006-6535
    Kostantin Khorenko discovered an invalid error path in dev_queue_xmit()
    which could be exploited by a local user to cause data corruption.
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
The following matrix explains which kernel version for which architect
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1304');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1304] DSA-1304-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1304-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge6');
deb_check(prefix: 'hostap-modules-2.4.27-3-386', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.4.27-3-586tsc', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.4.27-3-686', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.4.27-3-686-smp', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.4.27-3-k6', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.4.27-3-k7', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.4.27-3-k7-smp', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.6.8-4-386', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.6.8-4-686', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.6.8-4-686-smp', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.6.8-4-k7', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'hostap-modules-2.6.8-4-k7-smp', release: '3.1', reference: '0.3.7-1sarge2');
deb_check(prefix: 'kernel-build-2.6.8-4', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-build-2.6.8-4-power3', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-build-2.6.8-4-power3-smp', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-build-2.6.8-4-power4', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-build-2.6.8-4-power4-smp', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-build-2.6.8-4-powerpc', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-build-2.6.8-4-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-13', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-13-amd64-generic', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-13-amd64-k8', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-13-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-13-em64t-p4', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-13-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-32', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-32-smp', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-386', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-64', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-64-smp', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-686', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-686-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-generic', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-itanium', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-itanium-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-k7', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-k7-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-mckinley', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-sparc32', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-sparc64', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-headers-2.6.8-4-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6.8-13-amd64-generic', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-13-amd64-k8', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-13-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-13-em64t-p4', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-13-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-32', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-32-smp', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-386', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-64', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-64-smp', release: '3.1', reference: '2.6.8-6sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-686', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-686-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-generic', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-itanium', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-itanium-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-k7', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-k7-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-mckinley', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-power3', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-power3-smp', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-power4', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-power4-smp', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-powerpc', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-s390', release: '3.1', reference: '2.6.8-5sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-s390-tape', release: '3.1', reference: '2.6.8-5sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-s390x', release: '3.1', reference: '2.6.8-5sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-smp', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-sparc32', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-sparc64', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-image-2.6.8-4-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge7');
deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge7');
deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge7');
deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge7');
deb_check(prefix: 'mol-modules-2.6.8-4-powerpc', release: '3.1', reference: '0.9.70+2.6.8+12sarge2');
deb_check(prefix: 'mol-modules-2.6.8-4-powerpc-smp', release: '3.1', reference: '0.9.70+2.6.8+12sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

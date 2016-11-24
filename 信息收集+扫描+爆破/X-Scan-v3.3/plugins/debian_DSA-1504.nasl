# This script was automatically generated from the dsa-1504
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31148);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1504");
 script_cve_id("CVE-2006-5823", "CVE-2006-6054", "CVE-2006-6058", "CVE-2006-7203", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1504 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code.  The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2006-5823
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted cramfs filesystem.
CVE-2006-6054
    LMH reported a potential local DoS which could be exploited by a malicious
    user with the privileges to mount and read a corrupted ext2 filesystem.
CVE-2006-6058
    LMH reported an issue in the minix filesystem that allows local users
    with mount privileges to create a DoS (printk flood) by mounting a
    specially crafted corrupt filesystem.
CVE-2006-7203
    OpenVZ Linux kernel team reported an issue in the smbfs filesystem which
    can be exploited by local users to cause a DoS (oops) during mount.
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
CVE-2007-2525
    Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused
    by releasing a socket before PPPIOCGCHAN is called upon it. This could
    be used by a local user to DoS a system by consuming all available memory.
CVE-2007-3105
    The PaX Team discovered a potential buffer overflow in the random number
    generator which may permit local users to cause a denial of service or
    gain additional privileges. This issue is not believed to effect default
    Debian installations where only root has sufficient privileges to exploit
    it.
CVE-2007-3739
    Adam Litke reported a potential local denial of service (oops) on
    powerpc platforms resulting from unchecked VMA expansion into address
    space reserved for hugetlb pages.
CVE-2007-3740
    Steve French reported that CIFS filesystems with CAP_UNIX enabled 
    were not honoring a process\' umask which may lead to unintentionally
    relaxed permissions.
CVE-2007-3848
    Wojciech Purczynski discovered that pdeath_signal was not being reset
    properly under certain conditions which may allow local users to gain
    privileges by sending arbitrary signals to suid binaries.
CVE-2007-4133
    Hugh Dickins discovered a potential local DoS (panic) in hugetlbfs.
    A misconversion of hugetlb_vmtruncate_list to prio_tree may allow
    local users to trigger a BUG_ON() call in exit_mmap.
CVE-2007-4308
    Alan Cox reported an issue in the aacraid driver that allows unprivileged
    local users to make ioctl calls which should be restricted to admin
    privileges.
CVE-2007-4573
    Wojciech Purczynski discovered a vulnerability that can be exploite
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1504');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and reboot
the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1504] DSA-1504-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1504-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge8');
deb_check(prefix: 'kernel-build-2.6.8-4', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-build-2.6.8-4-power3', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-build-2.6.8-4-power3-smp', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-build-2.6.8-4-power4', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-build-2.6.8-4-power4-smp', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-build-2.6.8-4-powerpc', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-build-2.6.8-4-powerpc-smp', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-13', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-13-amd64-generic', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-13-amd64-k8', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-13-amd64-k8-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-13-em64t-p4', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-13-em64t-p4-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-32', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-32-smp', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-386', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-64', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-64-smp', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-686', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-686-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-generic', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-itanium', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-itanium-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-k7', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-k7-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-mckinley', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-mckinley-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-sparc32', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-sparc64', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-4-sparc64-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-13-amd64-generic', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-13-amd64-k8', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-13-amd64-k8-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-13-em64t-p4', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-13-em64t-p4-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-32', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-32-smp', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-386', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-64', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-64-smp', release: '3.1', reference: '2.6.8-7sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-686', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-686-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-generic', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-itanium', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-itanium-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-k7', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-k7-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-mckinley', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-mckinley-smp', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-power3', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-power3-smp', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-power4', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-power4-smp', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-powerpc', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-powerpc-smp', release: '3.1', reference: '2.6.8-13sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-s390', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-s390-tape', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-s390x', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-smp', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-sparc32', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-sparc64', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-4-sparc64-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-6sarge1');
deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-17sarge1');
deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-17sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-922
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22788);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "922");
 script_bugtraq_id(14477);
 script_bugtraq_id(15527);
 script_bugtraq_id(15528);
 script_bugtraq_id(15533);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-922 security update');
 script_set_attribute(attribute: 'description', value:
'Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2004-2302
    A race condition in the sysfs filesystem allows local users to
    read kernel memory and cause a denial of service (crash).
CVE-2005-0756
    Alexander Nyberg discovered that the ptrace() system call does not
    properly verify addresses on the amd64 architecture which can be
    exploited by a local attacker to crash the kernel.
CVE-2005-0757
    A problem in the offset handling in the xattr file system code for
    ext3 has been discovered that may allow users on 64-bit systems
    that have access to an ext3 filesystem with extended attributes to
    cause the kernel to crash.
CVE-2005-1265
    Chris Wright discovered that the mmap() function could create
    illegal memory maps that could be exploited by a local user to
    crash the kernel or potentially execute arbitrary code.
CVE-2005-1761
    A vulnerability on the IA-64 architecture can lead local attackers
    to overwrite kernel memory and crash the kernel.
CVE-2005-1762
    A vulnerability has been discovered in the ptrace() system call on
    the amd64 architecture that allows a local attacker to cause the
    kernel to crash.
CVE-2005-1763
    A buffer overflow in the ptrace system call for 64-bit
    architectures allows local users to write bytes into arbitrary
    kernel memory.
CVE-2005-1765
    Zou Nan Hai has discovered that a local user could cause the
    kernel to hang on the amd64 architecture after invoking syscall()
    with specially crafted arguments.
CVE-2005-1767
    A vulnerability has been discovered in the stack segment fault
    handler that could allow a local attacker to cause a stack exception
    that will lead the kernel to crash under certain circumstances.
CVE-2005-2456
    Balazs Scheidler discovered that a local attacker could call
    setsockopt() with an invalid xfrm_user policy message which would
    cause the kernel to write beyond the boundaries of an array and
    crash.
CVE-2005-2458
    Vladimir Volovich discovered a bug in the zlib routines which are
    also present in the Linux kernel and allows remote attackers to
    crash the kernel.
CVE-2005-2459
    Another vulnerability has been discovered in the zlib routines
    which are also present in the Linux kernel and allows remote
    attackers to crash the kernel.
CVE-2005-2548
    Peter Sandstrom noticed that snmpwalk from a remote host could
    cause a denial of service (kernel oops from null dereference) via
    certain UDP packets that lead to a function call with the wrong
    argument.
CVE-2005-2801
    Andreas Gruenbacher discovered a bug in the ext2 and ext3 file
    systems.  When data areas are to be shared among two inodes not
    all information were compared for equality, which could expose
    wrong ACLs for files.
CVE-2005-2872
    Chad Walstrom discovered that the ipt_recent kernel module on
    64-bit processors such as AMD64 allows remote attackers to cause a
    denial of service (kernel panic)
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-922');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel package immediately and
reboot the machine.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA922] DSA-922-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2004-2302", "CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1265", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1763", "CVE-2005-1765", "CVE-2005-1767", "CVE-2005-2456", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2548", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3105", "CVE-2005-3106", "CVE-2005-3107", "CVE-2005-3108", "CVE-2005-3109", "CVE-2005-3110", "CVE-2005-3271", "CVE-2005-3272", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");
 script_summary(english: "DSA-922-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-build-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power3', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power3-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power4', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-power4-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-powerpc', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-build-2.6.8-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-headers-2.6.8', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-generic', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-k8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-em64t-p4', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-headers-2.6.8-11-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge1');
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
deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-amd64-generic', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-amd64-k8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-em64t-p4', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-image-2.6.8-11-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge1');
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
deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power3', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power3-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power4', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-power4-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-powerpc', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge1');
deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge1');
deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge1');
deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge1');
deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

# This script was automatically generated from the dsa-1787
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38668);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1787");
 script_cve_id("CVE-2008-4307", "CVE-2008-5079", "CVE-2008-5395", "CVE-2008-5700", "CVE-2008-5701", "CVE-2008-5702", "CVE-2009-0028");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1787 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-4307
    Bryn M. Reeves reported a denial of service in the NFS filesystem.
    Local users can trigger a kernel BUG() due to a race condition in
    the do_setlk function.
CVE-2008-5079
    Hugo Dias reported a DoS condition in the ATM subsystem that can
    be triggered by a local user by calling the svc_listen function
    twice on the same socket and reading /proc/net/atm/*vc.
CVE-2008-5395
    Helge Deller discovered a denial of service condition that allows
    local users on PA-RISC systems to crash a system by attempting to
    unwind a stack contiaining userspace addresses.
CVE-2008-5700
    Alan Cox discovered a lack of minimum timeouts on SG_IO requests,
    which allows local users of systems using ATA to cause a denial of
    service by forcing drives into PIO mode.
CVE-2008-5701
    Vlad Malov reported an issue on 64-bit MIPS systems where a local
    user could cause a system crash by crafing a malicious binary
    which makes o32 syscalls with a number less than 4000.
CVE-2008-5702
    Zvonimir Rakamaric reported an off-by-one error in the ib700wdt
    watchdog driver which allows local users to cause a buffer
    underflow by making a specially crafted WDIOC_SETTIMEOUT ioctl
    call.
CVE-2009-0028
    Chris Evans discovered a situation in which a child process can
    send an arbitrary signal to its parent.
CVE-2009-0029
    Christian Borntraeger discovered an issue effecting the alpha,
    mips, powerpc, s390 and sparc64 architectures that allows local
    users to cause a denial of service or potentially gain elevated
    privileges.
CVE-2009-0031
    Vegard Nossum discovered a memory leak in the keyctl subsystem
    that allows local users to cause a denial of service by consuming
    all of kernel memory.
CVE-2009-0065
    Wei Yongjun discovered a memory overflow in the SCTP
    implementation that can be triggered by remote users, permitting
    remote code execution.
CVE-2009-0269
    Duane Griffin provided a fix for an issue in the eCryptfs
    subsystem which allows local users to cause a denial of service
    (fault or memory corruption).
CVE-2009-0322
    Pavel Roskin provided a fix for an issue in the dell_rbu driver
    that allows a local user to cause a denial of service (oops) by
    reading 0 bytes from a sysfs entry.
CVE-2009-0675
    Roel Kluin discovered inverted logic in the skfddi driver that
    permits local, unprivileged users to reset the driver statistics.
CVE-2009-0676
    Clement LECIGNE discovered a bug in the sock_getsockopt function
    that may result in leaking sensitive kernel memory.
CVE-2009-0745
    Peter Kerwien discovered an issue in the ext4 filesystem that
    allows local users to cause a denial of service (kernel oops)
    during a resize operation.
CVE-2009-0834
    Roland McGrath discovered an issue on amd64 kernels that allows
    local users to circumvent system call audit configurations which
    filter based on the syscall numbers or argumen
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1787');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your linux-2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1787] DSA-1787-1 linux-2.6.24");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1787-1 linux-2.6.24");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");

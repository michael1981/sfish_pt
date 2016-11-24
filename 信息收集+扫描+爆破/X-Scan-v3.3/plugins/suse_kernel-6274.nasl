
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(39335);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-6274)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-6274");
 script_set_attribute(attribute: "description", value: "This kernel update for openSUSE 10.3 fixes some bugs and
several security problems.

The following security issues are fixed: A local denial of
service problem in the splice(2) system call.

CVE-2009-0834: The audit_syscall_entry function in the
Linux kernel on the x86_64 platform did not properly handle
(1) a 32-bit process making a 64-bit syscall or (2) a
64-bit process making a 32-bit syscall, which allows local
users to bypass certain syscall audit configurations via
crafted syscalls.

CVE-2009-1072: nfsd in the Linux kernel did not drop the
CAP_MKNOD capability before handling a user request in a
thread, which allows local users to create device nodes, as
demonstrated on a filesystem that has been exported with
the root_squash option.

CVE-2009-0835  The __secure_computing function in
kernel/seccomp.c in the seccomp subsystem in the Linux
kernel on the x86_64 platform, when CONFIG_SECCOMP is
enabled, does not properly handle (1) a 32-bit process
making a 64-bit syscall or (2) a 64-bit process making a
32-bit syscall, which allows local users to bypass intended
access restrictions via crafted syscalls that are
misinterpreted as (a) stat or (b) chmod.

CVE-2009-1439: Buffer overflow in fs/cifs/connect.c in CIFS
in the Linux kernel 2.6.29 and earlier allows remote
attackers to cause a denial of service (crash) or potential
code execution via a long nativeFileSystem field in a Tree
Connect response to an SMB mount request.

This requires that kernel can be made to mount a 'cifs'
filesystem from a malicious CIFS server.

CVE-2009-1337: The exit_notify function in kernel/exit.c in
the Linux kernel did not restrict exit signals when the
CAP_KILL capability is held, which allows local users to
send an arbitrary signal to a process by running a program
that modifies the exit_signal field and then uses an exec
system call to launch a setuid application.

CVE-2009-0859: The shm_get_stat function in ipc/shm.c in
the shm subsystem in the Linux kernel, when CONFIG_SHMEM is
disabled, misinterprets the data type of an inode, which
allows local users to cause a denial of service (system
hang) via an SHM_INFO shmctl call, as demonstrated by
running the ipcs program. (SUSE is enabling CONFIG_SHMEM,
so is by default not affected, the fix is just for
completeness).

CVE-2009-1265: Integer overflow in rose_sendmsg
(sys/net/af_rose.c) in the Linux kernel might allow
attackers to obtain sensitive information via a large
length value, which causes 'garbage' memory to be sent.

CVE-2009-0028: The clone system call in the Linux kernel
allows local users to send arbitrary signals to a parent
process from an unprivileged child process by launching an
additional child process with the CLONE_PARENT flag, and
then letting this new process exit.

CVE-2009-0676: The sock_getsockopt function in
net/core/sock.c in the Linux kernel does not initialize a
certain structure member, which allows local users to
obtain potentially sensitive information from kernel memory
via an SO_BSDCOMPAT getsockopt request.

CVE-2009-0322: drivers/firmware/dell_rbu.c in the Linux
kernel allows local users to cause a denial of service
(system crash) via a read system call that specifies zero
bytes from the (1) image_type or (2) packet_size file in
/sys/devices/platform/dell_rbu/.

CVE-2009-0269: fs/ecryptfs/inode.c in the eCryptfs
subsystem in the Linux kernel allows local users to cause a
denial of service (fault or memory corruption), or possibly
have unspecified other impact, via a readlink call that
results in an error, leading to use of a -1 return value as
an array index.

CVE-2009-0065: Buffer overflow in net/sctp/sm_statefuns.c
in the Stream Control Transmission Protocol (sctp)
implementation in the Linux kernel allows remote attackers
to have an unknown impact via an FWD-TSN (aka FORWARD-TSN)
chunk with a large stream ID.

CVE-2008-5702: Buffer underflow in the ibwdt_ioctl function
in drivers/watchdog/ib700wdt.c in the Linux kernel might
allow local users to have an unknown impact via a certain
/dev/watchdog WDIOC_SETTIMEOUT IOCTL call.

CVE-2008-4554: The do_splice_from function in fs/splice.c
in the Linux kernel does not reject file descriptors that
have the O_APPEND flag set, which allows local users to
bypass append mode and make arbitrary changes to other
locations in the file.

Some other non-security bugs were fixed, please see the RPM
changelog.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-6274");
script_end_attributes();

script_cve_id("CVE-2009-0834", "CVE-2009-1072", "CVE-2009-0835", "CVE-2009-1439", "CVE-2009-1337", "CVE-2009-0859", "CVE-2009-1265", "CVE-2009-0028", "CVE-2009-0676", "CVE-2009-0322", "CVE-2009-0269", "CVE-2009-0065", "CVE-2008-5702", "CVE-2008-4554");
script_summary(english: "Check for the kernel-6274 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.19-0.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

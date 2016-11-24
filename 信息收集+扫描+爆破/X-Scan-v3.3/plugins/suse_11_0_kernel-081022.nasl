
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(40010);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  kernel (2008-10-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kernel");
 script_set_attribute(attribute: "description", value: "This patch updates the openSUSE 11.0 kernel to the
2.6.25.18 stable release.

It also includes bugfixes and security fixes:

CVE-2008-4410: The vmi_write_ldt_entry function in
arch/x86/kernel/vmi_32.c in the Virtual Machine Interface
(VMI) in the Linux kernel 2.6.26.5 invokes write_idt_entry
where write_ldt_entry was intended, which allows local
users to cause a denial of service (persistent application
failure) via crafted function calls, related to the Java
Runtime Environment (JRE) experiencing improper LDT
selector state.

sctp: Fix kernel panic while process protocol violation
parameter.

CVE-2008-3528: The ext[234] filesystem code fails to
properly handle corrupted data structures. With a mounted
filesystem image or partition that have corrupted
dir->i_size and dir->i_blocks, a user performing either a
read or write operation on the mounted image or partition
can lead to a possible denial of service by spamming the
logfile.

CVE-2008-3526: Integer overflow in the
sctp_setsockopt_auth_key function in net/sctp/socket.c in
the Stream Control Transmission Protocol (sctp)
implementation in the Linux kernel allows remote attackers
to cause a denial of service (panic) or possibly have
unspecified other impact via a crafted sca_keylength field
associated with the SCTP_AUTH_KEY option.

CVE-2008-3525: Added missing capability checks in
sbni_ioctl().

CVE-2008-4576: SCTP in Linux kernel before 2.6.25.18 allows
remote attackers to cause a denial of service (OOPS) via an
INIT-ACK that states the peer does not support AUTH, which
causes the sctp_process_init function to clean up active
transports and triggers the OOPS when the T1-Init timer
expires.

CVE-2008-4445: The sctp_auth_ep_set_hmacs function in
net/sctp/auth.c in the Stream Control Transmission Protocol
(sctp) implementation in the Linux kernel before 2.6.26.4,
when the SCTP-AUTH extension is enabled, does not verify
that the identifier index is within the bounds established
by SCTP_AUTH_HMAC_ID_MAX, which allows local users to
obtain sensitive information via a crafted SCTP_HMAC_IDENT
IOCTL request involving the sctp_getsockopt function.

CVE-2008-3792: net/sctp/socket.c in the Stream Control
Transmission Protocol (sctp) implementation in the Linux
kernel 2.6.26.3 does not verify that the SCTP-AUTH
extension is enabled before proceeding with SCTP-AUTH API
functions, which allows attackers to cause a denial of
service (panic) via vectors that result in calls to (1)
sctp_setsockopt_auth_chunk, (2) sctp_setsockopt_hmac_ident,
(3) sctp_setsockopt_auth_key, (4)
sctp_setsockopt_active_key, (5) sctp_setsockopt_del_key,
(6) sctp_getsockopt_maxburst, (7)
sctp_getsockopt_active_key, (8)
sctp_getsockopt_peer_auth_chunks, or (9)
sctp_getsockopt_local_auth_chunks.

CVE-2008-4113: The sctp_getsockopt_hmac_ident function in
net/sctp/socket.c in the Stream Control Transmission
Protocol (sctp) implementation in the Linux kernel before
2.6.26.4, when the SCTP-AUTH extension is enabled, relies
on an untrusted length value to limit copying of data from
kernel memory, which allows local users to obtain sensitive
information via a crafted SCTP_HMAC_IDENT IOCTL request
involving the sctp_getsockopt function.

CVE-2008-3911: The proc_do_xprt function in
net/sunrpc/sysctl.c in the Linux kernel 2.6.26.3 does not
check the length of a certain buffer obtained from
userspace, which allows local users to overflow a
stack-based buffer and have unspecified other impact via a
crafted read system call for the
/proc/sys/sunrpc/transports file.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kernel");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=406656");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=403346");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=432488");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=432490");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=432490");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=409961");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=427244");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=417821");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=415372");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=419134");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=421321");
script_end_attributes();

 script_cve_id("CVE-2008-3525", "CVE-2008-3526", "CVE-2008-3528", "CVE-2008-3792", "CVE-2008-3911", "CVE-2008-4113", "CVE-2008-4410", "CVE-2008-4445", "CVE-2008-4576");
script_summary(english: "Check for the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-debug-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.25.18-0.2", release:"SUSE11.0", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.18-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.18-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

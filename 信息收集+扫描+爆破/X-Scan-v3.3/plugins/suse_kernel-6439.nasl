
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41540);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-6439)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-6439");
 script_set_attribute(attribute: "description", value: "This patch updates the SUSE Linux Enterprise 10 SP2 kernel
to fix various bugs and some security issues.

Following security issues were fixed: CVE-2009-2692: A
missing NULL pointer check in the socket sendpage function
can be used by local attackers to gain root privileges.

(No cve yet) A information leak from using sigaltstack was
fixed.

Enabled -fno-delete-null-pointer-checks to avoid optimizing
away NULL pointer checks and fixed Makefiles to make sure
-fwrapv is used everywhere.

CVE-2009-1758: The hypervisor_callback function in Xen
allows guest user applications to cause a denial of service
(kernel oops) of the guest OS by triggering a segmentation
fault in 'certain address ranges.'

CVE-2009-1389: A crash on r8169 network cards when
receiving large packets was fixed.

CVE-2009-1630: The nfs_permission function in fs/nfs/dir.c
in the NFS client implementation in the Linux kernel, when
atomic_open is available, does not check execute (aka EXEC
or MAY_EXEC) permission bits, which allows local users to
bypass permissions and execute files, as demonstrated by
files on an NFSv4 fileserver
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-6439");
script_end_attributes();

script_cve_id("CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1758", "CVE-2009-2692");
script_summary(english: "Check for the kernel-6439 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmi-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmipae-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.60-0.42.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

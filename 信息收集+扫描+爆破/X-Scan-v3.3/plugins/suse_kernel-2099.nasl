
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27290);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Kernel Update for SUSE Linux 10.1 (kernel-2099)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-2099");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2006-3745: A double userspace copy in a SCTP ioctl
  allows local attackers to overflow a buffer in the
  kernel, potentially allowing code execution and privilege
  escalation. [#199441]

- CVE-2006-4093: Local attackers were able to crash PowerPC
  systems with PPC970 processor using a not correctly
  disabled privileged instruction ('attn'). [#197810]

- CVE-2006-3468: Remote attackers able to access an NFS of
  a ext2 or ext3 filesystem can cause a denial of service
  (file system panic) via a crafted UDP packet with a V2
  lookup procedure that specifies a bad file handle (inode
  number), which triggers an error and causes an exported
  directory to be remounted read-only. [#192988]

Additionaly this kernel catches up to the SLE 10 state of
the kernel, with massive additional fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-2099");
script_end_attributes();

script_cve_id("CVE-2006-3745", "CVE-2006-4093", "CVE-2006-3468");
script_summary(english: "Check for the kernel-2099 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.21-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kexec-tools-1.101-32.19", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mkinitrd-1.2-106.19", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"multipath-tools-0.4.6-25.11", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"open-iscsi-0.5.545-9.15", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"udev-085-30.15", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-2099-patch-message-2-2099-1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

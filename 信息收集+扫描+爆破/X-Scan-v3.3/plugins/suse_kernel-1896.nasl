
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29484);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-1896)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-1896");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2006-3626: A race condition allows local users to
  gain root privileges by changing the file mode of
  /proc/self/ files in a way that causes those files (for
  instance /proc/self/environ) to become setuid root.
  [#192688]
- CVE-2006-2935: A stackbased buffer overflow in CDROM /
  DVD handling was fixed which could be used by a physical
  local attacker to crash the kernel or execute code within
  kernel context, depending on presence of automatic DVD
  handling in the system. [#190396]
- CVE-2006-2451: Due to an argument validation error in
  prctl(PR_SET_DUMPABLE) a local attacker can easily gain
  administrator (root) privileges. [#186980]

and the following non security bugs:

- Limit the maximum number of LUNs to 16384 [#185164]
- LSI 1030/MPT Fusion driver hang during error recovery --
  Optionally disable QAS [#180100]
- advance buffer pointers in h_copy_rdma() to avoid data
  corruption [#186444]
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-1896");
script_end_attributes();

script_cve_id("CVE-2006-2451", "CVE-2006-2935", "CVE-2006-3626");
script_summary(english: "Check for the kernel-1896 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.21-0.15", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.21-0.15", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.21-0.15", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.21-0.15", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.21-0.15", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.21-0.15", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

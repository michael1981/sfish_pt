
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42394);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.2 Security Update:  kernel (2009-10-28)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kernel");
 script_set_attribute(attribute: "description", value: "This is a openSUSE 11.2 RC1 kernel test update.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kernel");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=546918");
script_end_attributes();

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
if ( rpm_check( reference:"kernel-debug-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.3-3.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-vanilla-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-trace-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-trace-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-trace-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-trace-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-trace-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-trace-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-base-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.31.5-0.1.1", release:"SUSE11.2", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

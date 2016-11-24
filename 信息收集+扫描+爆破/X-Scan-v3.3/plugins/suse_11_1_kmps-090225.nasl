
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40251);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  kmps (2009-02-25)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kmps");
 script_set_attribute(attribute: "description", value: "This update contains kernel module packages for the first
openSUSE 11.1 kernel update.

It contains all kernel module packages.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kmps");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=444597");
script_end_attributes();

script_summary(english: "Check for the kmps package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"acx-kmp-debug-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-debug-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-default-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-default-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-pae-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-trace-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-trace-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-xen-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-xen-20080210_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-debug-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-debug-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-default-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-default-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-pae-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-trace-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-trace-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-xen-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-xen-1.1_2.6.27.19_3.2-114.65.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-debug-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-debug-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-default-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-default-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-pae-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-trace-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-trace-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-xen-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-xen-cvs20081020_2.6.27.19_3.2-1.32.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-default-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-default-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-pae-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-trace-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-trace-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-xen-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"brocade-bfa-kmp-xen-1.1.0.2_2.6.27.19_3.2-1.7.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-debug-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-debug-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-default-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-default-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-pae-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-trace-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-trace-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-xen-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-xen-2.3.6_2.6.27.19_3.2-1.49.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-debug-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-debug-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-default-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-default-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-pae-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-trace-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-trace-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-xen-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-xen-8.2.7_2.6.27.19_3.2-1.18.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-debug-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-default-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-default-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-pae-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-trace-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-trace-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-xen-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hci_usb-kmp-xen-0.1_2.6.27.19_3.2-2.47.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-debug-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-debug-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-default-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-default-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-pae-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-trace-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-trace-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-xen-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"intel-iamt-heci-kmp-xen-3.1.0.31_2.6.27.19_3.2-2.40.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-debug-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-debug-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-default-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-default-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-pae-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-trace-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-trace-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-xen-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-xen-0.4.15_2.6.27.19_3.2-89.11.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-debug-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-debug-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-default-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-default-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-pae-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-trace-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-trace-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-xen-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-xen-1.4.0pre1_2.6.27.19_3.2-2.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-default-78_2.6.27.19_3.2-6.6.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-default-78_2.6.27.19_3.2-6.6.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-pae-78_2.6.27.19_3.2-6.6.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-trace-78_2.6.27.19_3.2-6.6.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-trace-78_2.6.27.19_3.2-6.6.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-default-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-default-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-pae-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-trace-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-trace-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-xen-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"lirc-kmp-xen-0.8.4_2.6.27.19_3.2-0.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-default-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-default-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-pae-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-trace-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-trace-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-xen-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-xen-1.53_2.6.27.19_3.2-12.37.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-debug-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-debug-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-default-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-default-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-pae-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-trace-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ofed-kmp-trace-1.4_2.6.27.19_3.2-21.15.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-debug-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-debug-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-default-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-default-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-pae-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-trace-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-trace-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-xen-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-xen-20080627_2.6.27.19_3.2-1.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-debug-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-debug-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-default-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-default-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-pae-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-trace-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-trace-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-xen-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"oracleasm-kmp-xen-2.0.5_2.6.27.19_3.2-2.36.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-debug-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-debug-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-default-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-default-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-pae-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-trace-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-trace-0.44_2.6.27.19_3.2-227.56.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"quickcam-kmp-default-0.6.6_2.6.27.19_3.2-9.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"quickcam-kmp-default-0.6.6_2.6.27.19_3.2-9.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"quickcam-kmp-pae-0.6.6_2.6.27.19_3.2-9.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-2.0.6-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-2.0.6-2.8.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-guest-tools-2.0.6-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-guest-tools-2.0.6-2.8.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-default-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-default-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-pae-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.19_3.2-2.8.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-debug-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-debug-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-default-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-default-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-pae-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-trace-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-trace-2008.09.03_2.6.27.19_3.2-5.50.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-debug-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-debug-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-default-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-default-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-pae-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-trace-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-trace-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-xen-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wacom-kmp-xen-0.8.1_2.6.27.19_3.2-6.1.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xorg-x11-driver-virtualbox-ose-2.0.6-2.8.6", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xorg-x11-driver-virtualbox-ose-2.0.6-2.8.6", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

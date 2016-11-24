
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27262);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  hbedv-dazuko: Securityupdate to version 2.3.2 (hbedv-dazuko-kmp-bigsmp-2410)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch hbedv-dazuko-kmp-bigsmp-2410");
 script_set_attribute(attribute: "description", value: "This patch updates the Dazuko kernel module to version
2.3.2.

Several memory leaks and stability issues have been fixed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch hbedv-dazuko-kmp-bigsmp-2410");
script_end_attributes();

script_summary(english: "Check for the hbedv-dazuko-kmp-bigsmp-2410 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"hbedv-dazuko-kmp-bigsmp-2.3.2_2.6.16.27_0.6-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"hbedv-dazuko-kmp-debug-2.3.2_2.6.16.27_0.6-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"hbedv-dazuko-kmp-default-2.3.2_2.6.16.27_0.6-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"hbedv-dazuko-kmp-smp-2.3.2_2.6.16.27_0.6-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"hbedv-dazuko-kmp-xen-2.3.2_2.6.16.27_0.6-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"hbedv-dazuko-kmp-xenpae-2.3.2_2.6.16.27_0.6-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

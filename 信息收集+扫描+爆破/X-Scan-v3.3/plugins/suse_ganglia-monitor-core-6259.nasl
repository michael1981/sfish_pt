
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38857);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  fixed stack overflow in ganglia (CVE-2009-0241). (ganglia-monitor-core-6259)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ganglia-monitor-core-6259");
 script_set_attribute(attribute: "description", value: "A stack buffer overflow in ganglia's  buffer process_path
function has been fixed. CVE-2009-0241 has been assigned to
this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ganglia-monitor-core-6259");
script_end_attributes();

script_cve_id("CVE-2009-0241");
script_summary(english: "Check for the ganglia-monitor-core-6259 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ganglia-monitor-core-2.5.7-99.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ganglia-monitor-core-devel-2.5.7-99.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ganglia-monitor-core-gmetad-2.5.7-99.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ganglia-monitor-core-gmond-2.5.7-99.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ganglia-webfrontend-2.5.7-99.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

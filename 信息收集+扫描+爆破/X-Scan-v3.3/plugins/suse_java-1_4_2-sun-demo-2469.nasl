
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27277);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  java: Missing SUN Java packages 1.4.2 update 13 and 1.5.0 update 10 (java-1_4_2-sun-demo-2469)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-demo-2469");
 script_set_attribute(attribute: "description", value: "The SUN Java packages have been upgraded to 1.4.2 update 13
and 1.5.0 update 10 to fix various security problems, this
update contains the missing packages that were left out for
10.2.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-demo-2469");
script_end_attributes();

script_summary(english: "Check for the java-1_4_2-sun-demo-2469 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_update10-2.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update10-2.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

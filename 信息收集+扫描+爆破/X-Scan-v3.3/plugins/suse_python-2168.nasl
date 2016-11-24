
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27406);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  python: Fixed a buffer overflow in python's repr() function (python-2168)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch python-2168");
 script_set_attribute(attribute: "description", value: "A buffer overflow within python's repr() function has been
fixed. The CAN number CVE-2006-4980 has been assigned to
this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch python-2168");
script_end_attributes();

script_cve_id("CVE-2006-4980");
script_summary(english: "Check for the python-2168 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"python-2.4.2-18.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-32bit-2.4.2-18.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-64bit-2.4.2-18.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-devel-2.4.2-18.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27532);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  opal security update (opal-4531)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opal-4531");
 script_set_attribute(attribute: "description", value: "A bug in the SIP protocol handler could be exploited by
attackers to crash applications using opal (CVE-2007-4924).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch opal-4531");
script_end_attributes();

script_cve_id("CVE-2007-4924");
script_summary(english: "Check for the opal-4531 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opal-2.2.8-60.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opal-devel-2.2.8-60.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

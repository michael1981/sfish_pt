
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27281);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  jboss: Securityupdate to fix potential code execution. (jboss-2309)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch jboss-2309");
 script_set_attribute(attribute: "description", value: "This update fixes a problem in the JBOSS server where it
was possible to potentially execute code if the console
manager was enabled. (CVE-2006-5750)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch jboss-2309");
script_end_attributes();

script_cve_id("CVE-2006-5750");
script_summary(english: "Check for the jboss-2309 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"jboss-3.2.5-22.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

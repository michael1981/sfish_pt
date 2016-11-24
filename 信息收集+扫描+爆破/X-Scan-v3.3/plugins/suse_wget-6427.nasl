
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42038);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  wget: security update for 0 in SSL certificate subject name (wget-6427)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wget-6427");
 script_set_attribute(attribute: "description", value: "This update wget improves the handling of the  0-character
in the subject name of a SSL certificate.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch wget-6427");
script_end_attributes();

script_summary(english: "Check for the wget-6427 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wget-1.10.2-78.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

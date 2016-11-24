
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41555);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for libxml2 (libxml2-5755)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libxml2-5755");
 script_set_attribute(attribute: "description", value: "This update fixes an integer overflow in libxml2 that could
lead to memory corruption and arbitrary code execution.
(CVE-2008-4226) Thanks to: Drew Yao of Apple Product
Security
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch libxml2-5755");
script_end_attributes();

script_cve_id("CVE-2008-4226");
script_summary(english: "Check for the libxml2-5755 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"libxml2-2.6.23-15.13", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.6.23-15.13", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

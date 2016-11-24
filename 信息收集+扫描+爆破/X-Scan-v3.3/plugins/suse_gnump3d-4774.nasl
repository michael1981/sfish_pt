
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29245);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  gnump3d: improve password handling for plugins (gnump3d-4774)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gnump3d-4774");
 script_set_attribute(attribute: "description", value: "This update fixes a restriction bypass in gnump3d's
plugins. (CVE-2007-6130)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch gnump3d-4774");
script_end_attributes();

script_cve_id("CVE-2007-6130");
script_summary(english: "Check for the gnump3d-4774 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gnump3d-2.9.8-84.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

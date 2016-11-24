
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27233);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  gdm security update (gdm-2387)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gdm-2387");
 script_set_attribute(attribute: "description", value: "A format string bug in the program 'gdmchooser' could
potentially be
 exploited to execute code under a different
user id.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gdm-2387");
script_end_attributes();

script_summary(english: "Check for the gdm-2387 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gdm-2.16.1-36.2", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(33101);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  Prevents popup windows from being displayed on top of screen locked with xscreensaver (xscreensaver-5156)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xscreensaver-5156");
 script_set_attribute(attribute: "description", value: "This patch fixes problem with popup windows (usually from
instant messaging applications), which may appear on top of
xscreensaver while the screen is locked.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch xscreensaver-5156");
script_end_attributes();

script_summary(english: "Check for the xscreensaver-5156 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xscreensaver-5.03-24.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

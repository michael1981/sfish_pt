
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33896);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  gnome-screensaver: information leak (gnome-screensaver-5506)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gnome-screensaver-5506");
 script_set_attribute(attribute: "description", value: "This update of gnome-screensaver disallows local users to
read the contents of the clipboard for a locked screen
using ctrl-v. (CVE-2007-6389)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch gnome-screensaver-5506");
script_end_attributes();

script_cve_id("CVE-2007-6389");
script_summary(english: "Check for the gnome-screensaver-5506 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gnome-screensaver-2.20.0-6.6", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

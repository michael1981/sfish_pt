
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39433);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  irssi: fixed CVE-2009-1959 (off by one overflow) (irssi-6304)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch irssi-6304");
 script_set_attribute(attribute: "description", value: "Fixed a irssi off by one overflow in the event_wallops()
function. CVE-2009-1959 has been assigned to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch irssi-6304");
script_end_attributes();

script_cve_id("CVE-2009-1959");
script_summary(english: "Check for the irssi-6304 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"irssi-0.8.11-19.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"irssi-devel-0.8.11-19.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

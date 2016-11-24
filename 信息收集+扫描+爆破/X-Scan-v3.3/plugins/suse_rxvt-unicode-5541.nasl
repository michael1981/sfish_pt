
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34042);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  rxvt-unicode security update (rxvt-unicode-5541)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch rxvt-unicode-5541");
 script_set_attribute(attribute: "description", value: "It was possible to open a terminal on :0 when the
environment variable was not set. This could be exploited
by local users to hijack X11 connections (CVE-2008-1142).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch rxvt-unicode-5541");
script_end_attributes();

script_cve_id("CVE-2008-1142");
script_summary(english: "Check for the rxvt-unicode-5541 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"rxvt-unicode-8.3-16.2", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

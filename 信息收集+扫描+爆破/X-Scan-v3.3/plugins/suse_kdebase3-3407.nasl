
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29477);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for kdebase3 (kdebase3-3407)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kdebase3-3407");
 script_set_attribute(attribute: "description", value: "A problem with the interaction between the Flash Player and
the Konqueror webbrowser was fixed. The problem could lead
to keypresses leaking to the applet instead of the browser.
(CVE-2007-2022)

This update of khc_indexbuilder also restricts the commands
that can be executed with EGID 'man'.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch kdebase3-3407");
script_end_attributes();

script_cve_id("CVE-2007-2022");
script_summary(english: "Check for the kdebase3-3407 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kdebase3-3.5.1-69.35.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-3.5.1-69.35.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

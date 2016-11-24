
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27272);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  inkscape: Fixes format string bugs (inkscape-3062)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch inkscape-3062");
 script_set_attribute(attribute: "description", value: "Several format string problems where fixed in inkscape.

CVE-2007-1463: A format string vulnerability in Inkscape
allows user-assisted remote attackers to execute arbitrary
code via format string specifiers in a URI, which is not
properly handled by certain dialogs.

CVE-2007-1464: Format string vulnerability in the
whiteboard Jabber protocol in Inkscape allows user-assisted
remote attackers to execute arbitrary code via unspecified
vectors.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch inkscape-3062");
script_end_attributes();

script_cve_id("CVE-2007-1463", "CVE-2007-1464");
script_summary(english: "Check for the inkscape-3062 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"inkscape-0.44.1-26.2", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

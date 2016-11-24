
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34027);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  namazu UTF-7 XSS (namazu-5523)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch namazu-5523");
 script_set_attribute(attribute: "description", value: "This version upgrade is provided to fix a UTF-7
cross-site-scripting vulnerabilitiy. (CVE-2008-1468)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch namazu-5523");
script_end_attributes();

script_cve_id("CVE-2008-1468");
script_summary(english: "Check for the namazu-5523 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"namazu-2.0.18-24.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"namazu-cgi-2.0.18-24.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"namazu-devel-2.0.18-24.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

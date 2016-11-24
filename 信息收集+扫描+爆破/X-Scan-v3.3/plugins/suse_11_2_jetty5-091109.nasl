
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42463);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.2 Security Update:  jetty5 (2009-11-09)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for jetty5");
 script_set_attribute(attribute: "description", value: "This update fixes a directory traversal bug in jetty5's
HTTP server. (CVE-2009-1523: CVSS v2 Base Score: 7.1)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for jetty5");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=551802");
script_end_attributes();

 script_cve_id("CVE-2009-1523");
script_summary(english: "Check for the jetty5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"jetty5-5.1.14-3.7.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"jetty5-demo-5.1.14-3.7.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"jetty5-javadoc-5.1.14-3.7.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"jetty5-manual-5.1.14-3.7.1", release:"SUSE11.2", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

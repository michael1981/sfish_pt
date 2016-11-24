
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41386);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  evolution (2009-04-16)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for evolution");
 script_set_attribute(attribute: "description", value: "camel's NTLM SASL authentication mechanism as used by
evolution did not properly validate server's challenge
packets (CVE-2009-0582). 

This update also includes the following non-security fixes:

- Fixes a critical crasher in mailer component. 
- Fixes creation of recurrence monthly items in GroupWise. 
- Includes fixes for some usability issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for evolution");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=475541");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=419303");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=479908");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=480091");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=477697");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=484213");
script_end_attributes();

 script_cve_id("CVE-2009-0582");
script_summary(english: "Check for the evolution package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"evolution-data-server-2.24.1.1-11.8.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"evolution-data-server-lang-2.24.1.1-11.8.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gtkhtml2-3.24.1.1-3.23.2", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gtkhtml2-lang-3.24.1.1-3.23.2", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"evolution-2.24.1.1-15.8.4", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"evolution-data-server-2.24.1.1-11.8.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"evolution-data-server-lang-2.24.1.1-11.8.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"evolution-lang-2.24.1.1-15.8.4", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.24.1.1-15.8.4", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gtkhtml2-3.24.1.1-3.23.2", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gtkhtml2-lang-3.24.1.1-3.23.2", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

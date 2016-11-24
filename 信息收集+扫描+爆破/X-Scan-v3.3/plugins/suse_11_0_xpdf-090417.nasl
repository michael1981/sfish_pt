
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40159);
 script_version("$Revision: 1.5 $");
 script_name(english: "SuSE 11.0 Security Update:  xpdf (2009-04-17)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for xpdf");
 script_set_attribute(attribute: "description", value: "Specially crafted PDF files could lead to crashes, make the
viewer run into an infinite loop or potentially even allow
execution of arbitrary code.

(CVE-2009-0165, CVE-2009-0146, CVE-2009-0147,
CVE-2009-0166, CVE-2009-0799, CVE-2009-0800, CVE-2009-1179,
CVE-2009-1180, CVE-2009-1181, CVE-2009-1182, CVE-2009-1183)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for xpdf");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=485892");
script_end_attributes();

 script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
script_summary(english: "Check for the xpdf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xpdf-3.02-95.4", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xpdf-3.02-95.4", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xpdf-tools-3.02-95.4", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xpdf-tools-3.02-95.4", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

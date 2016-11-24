
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40883);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.1 Security Update:  OpenOffice_org-math (2009-08-10)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for OpenOffice_org-math");
 script_set_attribute(attribute: "description", value: "Secunia reported an integer underflow (CVE-2009-0200) and a
buffer overflow (CVE-2009-0201) that could be triggered
while parsing Word documents.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for OpenOffice_org-math");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514085");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=514089");
script_end_attributes();

 script_cve_id("CVE-2009-0200", "CVE-2009-0201");
script_summary(english: "Check for the OpenOffice_org-math package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"OpenOffice_org-math-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-math-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-devel-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-devel-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-l10n-prebuilt-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-writer-l10n-prebuilt-3.0.0.9-2.8.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

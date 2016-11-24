
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(40227);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.1 Security Update:  gstreamer-0_10-plugins-good (2009-02-18)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for gstreamer-0_10-plugins-good");
 script_set_attribute(attribute: "description", value: "gstreamer-0_10: several heap overflows (CVE-2009-0386,
CVE-2009-0387,CVE-2009-0397) have been fixed. Remote
attackers could exploit these to execute arbitrary code via
QuickTime media files.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for gstreamer-0_10-plugins-good");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=469336");
script_end_attributes();

 script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
script_summary(english: "Check for the gstreamer-0_10-plugins-good package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-0.10.10-3.21.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-0.10.10-3.21.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-doc-0.10.10-3.21.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-doc-0.10.10-3.21.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-extra-0.10.10-3.21.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-extra-0.10.10-3.21.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-lang-0.10.10-3.21.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-good-lang-0.10.10-3.21.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

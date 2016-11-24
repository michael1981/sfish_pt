
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41379);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  curl (2009-08-07)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for curl");
 script_set_attribute(attribute: "description", value: "This update of libcurl2 fixes the 0-character handling in
the subject name of a SSL certificate. This bug could be
used to execute an undetected man-in-the-middle-attack.
(CVE-2009-2417)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for curl");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=527990");
script_end_attributes();

 script_cve_id("CVE-2009-2417");
script_summary(english: "Check for the curl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"curl-7.19.0-11.22.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"keyutils-libs-1.2-107.22", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libcurl4-7.19.0-11.22.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libidn-1.10-3.18", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"curl-7.19.0-11.22.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"keyutils-libs-1.2-107.22", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libcurl4-7.19.0-11.22.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libidn-1.10-3.18", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

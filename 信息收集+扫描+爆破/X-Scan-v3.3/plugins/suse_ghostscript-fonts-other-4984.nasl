
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31321);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for Ghostscript (ghostscript-fonts-other-4984)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ghostscript-fonts-other-4984");
 script_set_attribute(attribute: "description", value: "A stackbased buffer overflow was fixed in the ghostscript
interpreter, which potentially could be used to execute
code or at least crash ghostscript. (CVE-2008-0411)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ghostscript-fonts-other-4984");
script_end_attributes();

script_cve_id("CVE-2008-0411");
script_summary(english: "Check for the ghostscript-fonts-other-4984 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ghostscript-fonts-other-8.15.3-18.13", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-rus-8.15.3-18.13", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-std-8.15.3-18.13", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-library-8.15.3-18.13", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-omni-8.15.3-18.13", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-x11-8.15.3-18.13", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-4.2.7-62.13.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-devel-4.2.7-62.14.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-other-8.15.3-18.13", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-std-8.15.3-18.13", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-library-8.15.3-18.13", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-x11-8.15.3-18.13", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-4.2.7-62.13.6", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

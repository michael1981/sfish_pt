
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27224);
 script_version ("$Revision: 1.14 $");
 script_name(english: "SuSE Security Update:  fix integer overflows in freetype 2 (freetype2-1608)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch freetype2-1608");
 script_set_attribute(attribute: "description", value: "Fixes for: CVE-2006-0747, CVE-2006-1054, CVE-2006-1861, 
CVE-2006-2493, CVE-2006-2661.  This patch fixes a few 
integer overflows in freetype 2. Without this patch it is 
possible to create font files which make freetype 2 crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch freetype2-1608");
script_end_attributes();

 script_cve_id("CVE-2006-0747", "CVE-2006-1861");
script_summary(english: "Check for the freetype2-1608 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"freetype2-2.1.10-18.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"freetype2-32bit-2.1.10-18.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"freetype2-64bit-2.1.10-18.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.10-18.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"freetype2-devel-32bit-2.1.10-18.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"freetype2-devel-64bit-2.1.10-18.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

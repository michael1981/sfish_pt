
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(39389);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  cups: Fixed multiple integer overflows in 'pdftops' filter  (CVE-2009-0791) and a ipp DoS (CVE-2009-0949). (cups-6285)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch cups-6285");
 script_set_attribute(attribute: "description", value: "The 'pdftops'  was prone to several integer overflows
(CVE-2009-0791). The cups daemon could crash when receiving
IPP requests with multiple unsupported tags (CVE-2009-0949).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch cups-6285");
script_end_attributes();

script_cve_id("CVE-2009-0791", "CVE-2009-0949");
script_summary(english: "Check for the cups-6285 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"cups-1.2.12-22.24", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-client-1.2.12-22.24", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-devel-1.2.12-22.24", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-1.2.12-22.24", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-32bit-1.2.12-22.24", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-64bit-1.2.12-22.24", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

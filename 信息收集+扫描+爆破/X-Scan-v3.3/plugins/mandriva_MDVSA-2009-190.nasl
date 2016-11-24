
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40465);
 script_version("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:190: OpenEXR");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:190 (OpenEXR).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in OpenEXR:
Multiple integer overflows in OpenEXR 1.2.2 and 1.6.1
allow context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via unspecified
vectors that trigger heap-based buffer overflows, related to (1)
the Imf::PreviewImage::PreviewImage function and (2) compressor
constructors. NOTE: some of these details are obtained from third
party information (CVE-2009-1720).
The decompression implementation in the Imf::hufUncompress function in
OpenEXR 1.2.2 and 1.6.1 allows context-dependent attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via vectors that trigger a free of an uninitialized pointer
(CVE-2009-1721).
This update provides fixes for these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:190");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1720", "CVE-2009-1721");
script_summary(english: "Check for the version of the OpenEXR package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libOpenEXR6-1.6.1-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libOpenEXR-devel-1.6.1-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"OpenEXR-1.6.1-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libOpenEXR6-1.6.1-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libOpenEXR-devel-1.6.1-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"OpenEXR-1.6.1-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libOpenEXR6-1.6.1-3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libOpenEXR-devel-1.6.1-3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"OpenEXR-1.6.1-3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"OpenEXR-", release:"MDK2008.1")
 || rpm_exists(rpm:"OpenEXR-", release:"MDK2009.0")
 || rpm_exists(rpm:"OpenEXR-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1720", value:TRUE);
 set_kb_item(name:"CVE-2009-1721", value:TRUE);
}
exit(0, "Host is not affected");

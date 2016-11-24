
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37585);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:019: imlib2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:019 (imlib2).");
 script_set_attribute(attribute: "description", value: "A vulnerability have been discovered in the load function of the XPM
loader for imlib2, which allows attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a crafted XPM file
(CVE-2008-5187).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:019");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5187");
script_summary(english: "Check for the version of the imlib2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"imlib2-data-1.4.0.003-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.4.0.003-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.4.0.003-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.4.0.003-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2-devel-1.4.0.003-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib2-data-1.4.0.003-4.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.4.0.003-4.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.4.0.003-4.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.4.0.003-4.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2-devel-1.4.0.003-4.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib2-data-1.4.1.000-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.4.1.000-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.4.1.000-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.4.1.000-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2-devel-1.4.1.000-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"imlib2-", release:"MDK2008.0")
 || rpm_exists(rpm:"imlib2-", release:"MDK2008.1")
 || rpm_exists(rpm:"imlib2-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-5187", value:TRUE);
}
exit(0, "Host is not affected");

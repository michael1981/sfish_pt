
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39324);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:132: libsndfile");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:132 (libsndfile).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in libsndfile:
Heap-based buffer overflow in voc_read_header in libsndfile 1.0.15
through 1.0.19, as used in Winamp 5.552 and possibly other media
programs, allows remote attackers to cause a denial of service
(application crash) and possibly execute arbitrary code via a VOC
file with an invalid header value (CVE-2009-1788).
Heap-based buffer overflow in aiff_read_header in libsndfile 1.0.15
through 1.0.19, as used in Winamp 5.552 and possibly other media
programs, allows remote attackers to cause a denial of service
(application crash) and possibly execute arbitrary code via an AIFF
file with an invalid header value (CVE-2009-1791).
This update provides fixes for these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:132");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1788", "CVE-2009-1791");
script_summary(english: "Check for the version of the libsndfile package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsndfile1-1.0.18-1.pre20.1.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-devel-1.0.18-1.pre20.1.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-progs-1.0.18-1.pre20.1.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-static-devel-1.0.18-1.pre20.1.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile1-1.0.18-2.pre22.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-devel-1.0.18-2.pre22.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-progs-1.0.18-2.pre22.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-static-devel-1.0.18-2.pre22.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile1-1.0.19-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-devel-1.0.19-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-progs-1.0.19-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsndfile-static-devel-1.0.19-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libsndfile-", release:"MDK2008.1")
 || rpm_exists(rpm:"libsndfile-", release:"MDK2009.0")
 || rpm_exists(rpm:"libsndfile-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1788", value:TRUE);
 set_kb_item(name:"CVE-2009-1791", value:TRUE);
}
exit(0, "Host is not affected");

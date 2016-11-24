
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14796);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:102: ImageMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:102 (ImageMagick).");
 script_set_attribute(attribute: "description", value: "Several buffer overflow vulnerabilities in ImageMagick were discovered
by Marcus Meissner from SUSE. These vulnerabilities would allow an
attacker to create a malicious image or video file in AVI, BMP, or DIB
formats which could crash the reading process. It may be possible to
create malicious images that could also allow for the execution of
arbitray code with the privileges of the invoking user or process.
The updated packages provided are patched to correct these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:102");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0827");
script_summary(english: "Check for the version of the ImageMagick package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ImageMagick-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-devel-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-devel-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"MDK10.0")
 || rpm_exists(rpm:"ImageMagick-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0827", value:TRUE);
}
exit(0, "Host is not affected");

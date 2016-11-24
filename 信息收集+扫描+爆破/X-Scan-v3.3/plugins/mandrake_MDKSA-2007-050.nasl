
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24753);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:050-1: mozilla-firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:050-1 (mozilla-firefox).");
 script_set_attribute(attribute: "description", value: "A number of security vulnerabilities have been discovered and corrected
in the latest Mozilla Firefox program, version 1.5.0.10.
This update provides the latest Firefox to correct these issues.
Update:
A regression was found in the latest Firefox packages provided where
changes to library paths caused applications that depended on the NSS
libraries (such as Thunderbird and Evolution) to fail to start or fail
to load certain SSL-related security components. These new packages
correct that problem and we apologize for any inconvenience the
previous update may have caused.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:050-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092");
script_summary(english: "Check for the version of the mozilla-firefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmozilla-firefox1.5.0.10-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmozilla-firefox1.5.0.10-devel-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnspr4-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnspr4-static-devel-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-1.5.0.10-2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-6077", value:TRUE);
 set_kb_item(name:"CVE-2007-0008", value:TRUE);
 set_kb_item(name:"CVE-2007-0009", value:TRUE);
 set_kb_item(name:"CVE-2007-0775", value:TRUE);
 set_kb_item(name:"CVE-2007-0777", value:TRUE);
 set_kb_item(name:"CVE-2007-0778", value:TRUE);
 set_kb_item(name:"CVE-2007-0779", value:TRUE);
 set_kb_item(name:"CVE-2007-0780", value:TRUE);
 set_kb_item(name:"CVE-2007-0800", value:TRUE);
 set_kb_item(name:"CVE-2007-0981", value:TRUE);
 set_kb_item(name:"CVE-2007-0995", value:TRUE);
 set_kb_item(name:"CVE-2007-0996", value:TRUE);
 set_kb_item(name:"CVE-2007-1092", value:TRUE);
}
exit(0, "Host is not affected");

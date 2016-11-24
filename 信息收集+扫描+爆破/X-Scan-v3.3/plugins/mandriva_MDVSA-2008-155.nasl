
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36242);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:155-1: mozilla-thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:155-1 (mozilla-thunderbird).");
 script_set_attribute(attribute: "description", value: "A number of security vulnerabilities have been discovered and
corrected in the latest Mozilla Thunderbird program, version 2.0.0.16
(CVE-2008-1233, CVE-2008-1234, CVE-2008-1235, CVE-2008-1236,
CVE-2008-1237, CVE-2008-2785, CVE-2008-2798, CVE-2008-2799,
CVE-2008-2802, CVE-2008-2803, CVE-2008-2807, CVE-2008-2809,
CVE-2008-2811).
This update provides the latest Thunderbird to correct these issues.
It also provides Thunderbird 2.x for Corporate 3.0 systems.
Update:
The previous update provided the incorrect version of the enigmail
locale files. This version correctly builds them for Thunderbird
2.0.0.16.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:155-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
script_summary(english: "Check for the version of the mozilla-thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ar-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ca-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-cs-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-de-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-el-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-es-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-es_AR-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-fi-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-fr-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-hu-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-it-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ja-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ko-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-nb-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-nl-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-pl-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-pt-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-pt_BR-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ro-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ru-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-sk-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-sl-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-sv-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-tr-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-zh_CN-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-zh_TW-2.0.0.16-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ar-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ca-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-cs-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-de-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-el-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-es-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-es_AR-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-fi-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-fr-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-hu-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-it-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ja-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ko-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-nb-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-nl-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-pl-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-pt-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-pt_BR-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ro-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-ru-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-sk-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-sl-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-sv-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-tr-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-zh_CN-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-zh_TW-2.0.0.16-1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK2008.0")
 || rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1233", value:TRUE);
 set_kb_item(name:"CVE-2008-1234", value:TRUE);
 set_kb_item(name:"CVE-2008-1235", value:TRUE);
 set_kb_item(name:"CVE-2008-1236", value:TRUE);
 set_kb_item(name:"CVE-2008-1237", value:TRUE);
 set_kb_item(name:"CVE-2008-2785", value:TRUE);
 set_kb_item(name:"CVE-2008-2798", value:TRUE);
 set_kb_item(name:"CVE-2008-2799", value:TRUE);
 set_kb_item(name:"CVE-2008-2802", value:TRUE);
 set_kb_item(name:"CVE-2008-2803", value:TRUE);
 set_kb_item(name:"CVE-2008-2807", value:TRUE);
 set_kb_item(name:"CVE-2008-2809", value:TRUE);
 set_kb_item(name:"CVE-2008-2811", value:TRUE);
}
exit(0, "Host is not affected");

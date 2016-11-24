
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14018);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:034: rxvt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:034 (rxvt).");
 script_set_attribute(attribute: "description", value: "Digital Defense Inc. released a paper detailing insecurities in various
terminal emulators, including rxvt. Many of the features supported by
these programs can be abused when untrusted data is displayed on the
screen. This abuse can be anything from garbage data being displayed
to the screen or a system compromise.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:034");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0022", "CVE-2003-0023", "CVE-2003-0066");
script_summary(english: "Check for the version of the rxvt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rxvt-2.7.8-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-CJK-2.7.8-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-devel-2.7.8-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-2.7.8-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-CJK-2.7.8-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-devel-2.7.8-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-2.7.8-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-CJK-2.7.8-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rxvt-devel-2.7.8-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"rxvt-", release:"MDK8.2")
 || rpm_exists(rpm:"rxvt-", release:"MDK9.0")
 || rpm_exists(rpm:"rxvt-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0022", value:TRUE);
 set_kb_item(name:"CVE-2003-0023", value:TRUE);
 set_kb_item(name:"CVE-2003-0066", value:TRUE);
}
exit(0, "Host is not affected");

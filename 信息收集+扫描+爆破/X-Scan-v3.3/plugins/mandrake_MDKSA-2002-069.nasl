
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13969);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2002:069: gv");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:069 (gv).");
 script_set_attribute(attribute: "description", value: "A buffer overflow was discovered in gv versions 3.5.8 and earlier by
Zen Parse. The problem is triggered by scanning a file and can be
exploited by an attacker sending a malformed PostScript or PDF file.
This would result in arbitrary code being executed with the privilege of
the user viewing the file. ggv uses code derived from gv and has the
same vulnerability. These updates provide patched versions of gv and
ggv to fix the vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:069");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0838");
script_summary(english: "Check for the version of the gv package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ggv-1.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-18.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ggv-1.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-27.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ggv-1.1.94-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-27.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ggv-1.99.9-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-27.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gv-", release:"MDK8.0")
 || rpm_exists(rpm:"gv-", release:"MDK8.1")
 || rpm_exists(rpm:"gv-", release:"MDK8.2")
 || rpm_exists(rpm:"gv-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-0838", value:TRUE);
}
exit(0, "Host is not affected");

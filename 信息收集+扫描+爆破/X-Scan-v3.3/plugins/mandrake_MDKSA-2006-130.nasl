
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23881);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:130: kdelibs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:130 (kdelibs).");
 script_set_attribute(attribute: "description", value: "KDE Konqueror 3.5.1 and earlier allows remote attackers to cause a denial
of service (application crash) by calling the replaceChild method on a
DOM object, which triggers a null dereference, as demonstrated by calling
document.replaceChild with a 0 (zero) argument.
This issue does not affect Corporate 3.0.
Updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:130");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-3672");
script_summary(english: "Check for the version of the kdelibs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdelibs-common-3.4.2-31.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-doc-3.4.2-31.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.4.2-31.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.4.2-31.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3672", value:TRUE);
}
exit(0, "Host is not affected");

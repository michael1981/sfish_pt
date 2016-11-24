
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14065);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:083: eroaster");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:083 (eroaster).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in eroaster where it does not take any
security precautions when creating a temporary file for the lockfile.
This vulnerability could be exploited to overwrite arbitrary files with
the privileges of the user running eroaster.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:083");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0656");
script_summary(english: "Check for the version of the eroaster package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"eroaster-2.1.0-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"eroaster-2.1.0-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"eroaster-", release:"MDK9.0")
 || rpm_exists(rpm:"eroaster-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0656", value:TRUE);
}
exit(0, "Host is not affected");

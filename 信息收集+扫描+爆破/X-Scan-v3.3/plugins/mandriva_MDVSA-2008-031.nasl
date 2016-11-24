
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36549);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:031: xdg-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:031 (xdg-utils).");
 script_set_attribute(attribute: "description", value: "A vulnerability was found in xdg-open and xdg-email commands, which
allows remote attackers to execute arbitrary commands if the user is
tricked into trying to open a maliciously crafted URL.
The updated packages have been patched to prevent the issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:031");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-0386");
script_summary(english: "Check for the version of the xdg-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xdg-utils-1.0.1-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xdg-utils-1.0.2-3.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xdg-utils-", release:"MDK2007.1")
 || rpm_exists(rpm:"xdg-utils-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2008-0386", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20832);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:027: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:027 (gzip).");
 script_set_attribute(attribute: "description", value: "Zgrep in gzip before 1.3.5 does not properly sanitize arguments, which
allows local users to execute arbitrary commands via filenames that are
injected into a sed script.
This was previously corrected in MDKSA-2005:092, however the fix was
incomplete. These updated packages provide a more comprehensive fix
to the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:027");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0758");
script_summary(english: "Check for the version of the gzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gzip-1.2.4a-13.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-14.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-15.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK10.1")
 || rpm_exists(rpm:"gzip-", release:"MDK10.2")
 || rpm_exists(rpm:"gzip-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
}
exit(0, "Host is not affected");

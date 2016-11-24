
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14104);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:004: slocate");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:004 (slocate).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered by Patrik Hornik in slocate versions up
to and including 2.7 where a carefully crafted database could overflow
a heap-based buffer. This could be exploited by a local user to gain
privileges of the 'slocate' group. The updated packages contain a
patch from Kevin Lindsay that causes slocate to drop privileges before
reading a user-supplied database.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:004");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0848");
script_summary(english: "Check for the version of the slocate package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"slocate-2.7-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"slocate-", release:"MDK9.1")
 || rpm_exists(rpm:"slocate-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0848", value:TRUE);
}
exit(0, "Host is not affected");

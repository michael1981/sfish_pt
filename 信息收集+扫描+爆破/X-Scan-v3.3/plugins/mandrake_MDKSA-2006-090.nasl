
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21601);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:090: shadow-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:090 (shadow-utils).");
 script_set_attribute(attribute: "description", value: "A potential security problem was found in the useradd tool when it
creates a new user's mailbox due to a missing argument to the open()
call, resulting in the first permissions of the file being some random
garbage found on the stack, which could possibly be held open for
reading or writing before the proper fchmod() call is executed.
Packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:090");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-1174");
script_summary(english: "Check for the version of the shadow-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"shadow-utils-4.0.3-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"shadow-utils-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2006-1174", value:TRUE);
}
exit(0, "Host is not affected");

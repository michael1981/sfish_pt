
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16376);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:033: enscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:033 (enscript).");
 script_set_attribute(attribute: "description", value: "A vulnerability in the enscript program's handling of the epsf command
used to insert inline EPS file into a document was found. An attacker
could create a carefully crafted ASCII file which would make used of
the epsf pipe command in such a way that it could execute arbitrary
commands if the file was opened with enscript (CVE-2004-1184).
Additionally, flaws were found in enscript that could be abused by
executing enscript with carefully crafted command-line arguments.
These flaws only have a security impact if enscript is executed by
other programs and passed untrusted data from remote users
(CVE-2004-1185 and CVE-2004-1186).
The updated packages have been patched to prevent these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:033");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
script_summary(english: "Check for the version of the enscript package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"enscript-1.6.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"enscript-1.6.4-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"enscript-", release:"MDK10.0")
 || rpm_exists(rpm:"enscript-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1184", value:TRUE);
 set_kb_item(name:"CVE-2004-1185", value:TRUE);
 set_kb_item(name:"CVE-2004-1186", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21176);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:061: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:061 (mailman).");
 script_set_attribute(attribute: "description", value: "Scrubber.py, in Mailman 2.1.5 and earlier, when using email 2.5 (part
of Python), is susceptible to a DoS (mailman service stops delivering
for the list in question) if it encounters a badly formed mime
multipart message with only one part and that part has two blank lines
between the first boundary and the end boundary.
Updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:061");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-0052");
script_summary(english: "Check for the version of the mailman package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mailman-2.1.5-15.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2006-0052", value:TRUE);
}
exit(0, "Host is not affected");

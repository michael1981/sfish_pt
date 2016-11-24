
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16243);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:015: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:015 (mailman).");
 script_set_attribute(attribute: "description", value: "Florian Weimer discovered a vulnerability in Mailman, which can be
exploited by malicious people to conduct cross-site scripting attacks.
Input is not properly sanitised by 'scripts/driver' when returning error
pages. This can be exploited to execute arbitrary HTML or script code in
a user's browser session in context of a vulnerable site by tricking a user
into visiting a malicious web site or follow a specially crafted link.
(CVE-2004-1177).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:015");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1177");
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

if ( rpm_check( reference:"mailman-2.1.4-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-7.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.0")
 || rpm_exists(rpm:"mailman-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1177", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20453);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:222: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:222 (mailman).");
 script_set_attribute(attribute: "description", value: "Scrubber.py in Mailman 2.1.4 - 2.1.6 does not properly handle UTF8
character encodings in filenames of e-mail attachments, which allows
remote attackers to cause a denial of service. (CVE-2005-3573)
In addition, these versions of mailman have an issue where the server
will fail with an Overflow on bad date data in a processed message.
The version of mailman in Corporate Server 2.1 does not contain the
above vulnerable code.
Updated packages are patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:222");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3573", "CVE-2005-4153");
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

if ( rpm_check( reference:"mailman-2.1.5-7.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-15.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.6-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.1")
 || rpm_exists(rpm:"mailman-", release:"MDK10.2")
 || rpm_exists(rpm:"mailman-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3573", value:TRUE);
 set_kb_item(name:"CVE-2005-4153", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23909);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:165: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:165 (mailman).");
 script_set_attribute(attribute: "description", value: "A flaw was discovered in how Mailman handles MIME multipart messages
where an attacker could send a carefully-crafted MIME multipart
message to a Mailman-run mailing list causing that mailing list to
stop working (CVE-2006-2941).
As well, a number of XSS (cross-site scripting) issues were discovered
that could be exploited to perform XSS attacks against the Mailman
administrator (CVE-2006-3636).
Finally, a CRLF injection vulnerability allows remote attackers to
spoof messages in the error log (CVE-2006-4624).
Updated packages have been patched to address these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:165");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-2941", "CVE-2006-3636", "CVE-2006-4624");
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

if ( rpm_check( reference:"mailman-2.1.6-6.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2941", value:TRUE);
 set_kb_item(name:"CVE-2006-3636", value:TRUE);
 set_kb_item(name:"CVE-2006-4624", value:TRUE);
}
exit(0, "Host is not affected");

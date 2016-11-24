
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13912);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:004: stunnel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:004 (stunnel).");
 script_set_attribute(attribute: "description", value: "All versions of stunnel from 3.15 to 3.21c are vulnerable to format
string bugs in the functions which implement smtp, pop, and nntp client
negotiations. Using stunnel with the '-n service' option and the '-c'
client mode option, a malicious server could use the format sting
vulnerability to run arbitrary code as the owner of the current stunnel
process. Version 3.22 is not vulnerable to this bug.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:004");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0002");
script_summary(english: "Check for the version of the stunnel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"stunnel-3.22-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"stunnel-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0002", value:TRUE);
}
exit(0, "Host is not affected");

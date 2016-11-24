
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(26007);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:175: eggdrop");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:175 (eggdrop).");
 script_set_attribute(attribute: "description", value: "A stack-based buffer overflow in mod/server.mod/servrmsg.c in Eggdrop
1.6.18, and possibly earlier, allows user-assisted, malicious remote
IRC servers to execute arbitrary code via a long private message.
Updated packages fix this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:175");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-2807");
script_summary(english: "Check for the version of the eggdrop package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"eggdrop-1.6.17-3.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"eggdrop-1.6.17-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"eggdrop-", release:"MDK2007.0")
 || rpm_exists(rpm:"eggdrop-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-2807", value:TRUE);
}
exit(0, "Host is not affected");

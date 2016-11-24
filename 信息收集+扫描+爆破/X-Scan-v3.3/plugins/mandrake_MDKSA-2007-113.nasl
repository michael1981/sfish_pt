
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25431);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:113: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:113 (mutt).");
 script_set_attribute(attribute: "description", value: "A flaw in the way mutt processed certain APOP authentication requests
was discovered. By sending certain responses when mutt attempted to
authenticate again an APOP server, a remote attacker could possibly
obtain certain portions of the user's authentication credentials
(CVE-2007-1558).
A flaw in how mutt handled certain characters in gecos fields could
lead to a buffer overflow. A local user able to give themselves a
carefully crafted Real Name could potentially execute arbitrary code
if a victim used mutt to expand the attacker's alias (CVE-2007-2683).
Updated packages have been patched to address these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:113");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1558", "CVE-2007-2683");
script_summary(english: "Check for the version of the mutt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mutt-1.5.11-5.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-utf8-1.5.11-5.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-1.5.14-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-utf8-1.5.14-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"MDK2007.0")
 || rpm_exists(rpm:"mutt-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1558", value:TRUE);
 set_kb_item(name:"CVE-2007-2683", value:TRUE);
}
exit(0, "Host is not affected");

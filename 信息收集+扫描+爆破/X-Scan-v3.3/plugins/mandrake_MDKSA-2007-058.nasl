
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24808);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:058: ekiga");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:058 (ekiga).");
 script_set_attribute(attribute: "description", value: "A format string flaw was discovered in how ekiga processes certain
messages, which could permit a remote attacker that can connect to
ekiga to potentially execute arbitrary code with the privileges of
the user running ekiga. This is similar to the previous
CVE-2007-1006, but the original evaluation/patches were incomplete.
Updated package have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:058");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0999", "CVE-2007-1006");
script_summary(english: "Check for the version of the ekiga package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ekiga-2.0.3-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ekiga-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-0999", value:TRUE);
 set_kb_item(name:"CVE-2007-1006", value:TRUE);
}
exit(0, "Host is not affected");

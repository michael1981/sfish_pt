
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37370);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDKSA-2007:154: xine-ui");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:154 (xine-ui).");
 script_set_attribute(attribute: "description", value: "Format string vulnerability in the errors_create_window function in
errors.c in xine-ui allows attackers to execute arbitrary code via
unknown vectors. (CVE-2007-0254)
XINE 0.99.4 allows user-assisted remote attackers to cause a denial
of service (application crash) and possibly execute arbitrary code
via a certain M3U file that contains a long #EXTINF line and contains
format string specifiers in an invalid udp:// URI, possibly a variant
of CVE-2007-0017. (CVE-2007-0255)
Updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:154");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0017", "CVE-2007-0254", "CVE-2007-0255");
script_summary(english: "Check for the version of the xine-ui package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xine-ui-0.99.4-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-aa-0.99.4-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-fb-0.99.4-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xine-ui-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-0017", value:TRUE);
 set_kb_item(name:"CVE-2007-0254", value:TRUE);
 set_kb_item(name:"CVE-2007-0255", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37661);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:175: yelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:175 (yelp).");
 script_set_attribute(attribute: "description", value: "A format string vulnerability was discovered in yelp after version
2.19.90 and before 2.24 that could allow remote attackers to execute
arbitrary code via format string specifiers in an invalid URI on the
command-line or via URI helpers in Firefox, Evolution, or possibly
other programs (CVE-2008-3533).
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:175");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3533");
script_summary(english: "Check for the version of the yelp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"yelp-2.20.0-3.7mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"yelp-2.22.0-2.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"yelp-", release:"MDK2008.0")
 || rpm_exists(rpm:"yelp-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3533", value:TRUE);
}
exit(0, "Host is not affected");

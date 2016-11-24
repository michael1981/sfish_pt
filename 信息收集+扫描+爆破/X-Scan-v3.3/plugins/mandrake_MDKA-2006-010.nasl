
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24496);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2006:010: klamav");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2006:010 (klamav).");
 script_set_attribute(attribute: "description", value: "Klamav 0.32 is now available for Mandriva Linux 2006 that fixes a
number of problems with the previous version:
- fix the proxy configuration; password-less proxies can now be used
- fix media:/ vs. devices:/ difference on different KDE versions
- translation of HTML advisory files; English and Brazilian Portuguese
are now available
- fix translation for all programs; a new klamav.pot file generated
against the full string translation code
- full English and Brazilian Portuguese are now available
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2006:010");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the klamav package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"klamav-0.32-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

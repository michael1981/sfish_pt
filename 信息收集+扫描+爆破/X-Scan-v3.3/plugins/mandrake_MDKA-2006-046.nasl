
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24521);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2006:046: bootsplash");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2006:046 (bootsplash).");
 script_set_attribute(attribute: "description", value: "When multiple profiles are configured, they can be choosen in the
bootloader with the PROFILE keyword, but this needs a dedicated entry
or to append manually the profile at each boot. To ease the choice of
the profile during the boot time, Mandriva developed a frame buffer
menu in GTK to choose the profile.
Unfortunately in 2007, a miscompilation removed this application from
the bootsplash package, thus the only left method to choose a profile
was the bootloader one. This new package of bootsplash brings back the
'fbmenu' command which display the appropriate profile selection menu
during boot.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2006:046");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the bootsplash package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bootsplash-3.1.14-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

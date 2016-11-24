
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38096);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2009:004: rpmdrake");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2009:004 (rpmdrake).");
 script_set_attribute(attribute: "description", value: "This update fixes several minor issues with rpmdrake:
- it stops running with debuging perl pragmas, which should speed up
some things
- it makes edit-urpm-sources not drop the 'ignore' flag when updating
a medium (bug #44930)
- it makes edit-urpm-sources display the right type of altered
mirrorlist media (bug #44930)
- it makes rpmdrake list plasma applets in GUI package list too
(bug #45835)
It also enhances searching in rpmdrake by fixing a rare crash on
searching (bug #46225), by scrolling the group list to the search
category when displaying results, and by updating the GUI package list.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2009:004");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the rpmdrake package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rpmdrake-5.0.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rpmdrake-5.0.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

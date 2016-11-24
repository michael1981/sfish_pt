
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38142);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:131: rpmdrake");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:131 (rpmdrake).");
 script_set_attribute(attribute: "description", value: "This update fixes several minor issues in rpmdrake:
- it fixes a crash due to bad timing with the X server (#41010)
- it fix empty per importance lists of updates in rpmdrake (list
of all updates was OK, MandrivaUpdate was OK) (#41331) (regression
introduced in 3.95 on 2007-09-14)
- it makes rpmdrake only warn once per session when media XML metadata
are newer than synthesis: in that case rpmdrake complained for every
unsyncrhonized package (#42737)
- it fixes a crash when selecting all packages (#40025)
- it fixes a rare crash when canceling (#41970)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:131");
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

if ( rpm_check( reference:"rpmdrake-4.9.13.5-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rpmdrake-4.9.13.5-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

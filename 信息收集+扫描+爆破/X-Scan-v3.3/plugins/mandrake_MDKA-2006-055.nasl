
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24530);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2006:055: rpmdrake");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2006:055 (rpmdrake).");
 script_set_attribute(attribute: "description", value: "Several bugs were fixed in rpmdrake: - various people saw crashes due
to invalid UTF-8 strings (#26099) - edit-urpm-sources.pl didn't start
if urpmi.cfg did not exist (#27336) - MandrivaUpdate got several fixes:
o it was impossible to select an update where there was only one group
(#26135) o all updates are preselected by default (#25271) o all
security, bugfix & normal updates were not displayed in 'all updates'
mode (#27268) o default is now 'all updates' rather than 'security
updates'
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2006:055");
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

if ( rpm_check( reference:"park-rpmdrake-3.19-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rpmdrake-3.19-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

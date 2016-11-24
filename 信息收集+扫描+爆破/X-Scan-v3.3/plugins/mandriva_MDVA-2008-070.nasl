
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38007);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:070: dkms");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:070 (dkms).");
 script_set_attribute(attribute: "description", value: "The dkms-minimal package in Mandriva Linux 2008 Spring did not require
lsb-release. If lsb-release was not installed, the dkms modules were
installed in the standard location, instead of the intended /dkms or
/dkms-binary. This update fixes that issue.
Due to another bug, dkms would consider older installed binary dkms
modules as original modules when installing a newer version of the
module as a source dkms package, thus wrongly moving the binary
modules around. This update disables original_module handling, not
needed anymore since the rework of dkms system in 2008 Spring.
Dkms would also print an error message during an upgrade of binary
module packages, and under certain conditions an additional warning
message regarding multiple modules being found. This update removes
those harmless messages when they are not appropriate.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:070");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the dkms package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dkms-2.0.19-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dkms-minimal-2.0.19-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dkms-2.0.19-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dkms-minimal-2.0.19-4.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

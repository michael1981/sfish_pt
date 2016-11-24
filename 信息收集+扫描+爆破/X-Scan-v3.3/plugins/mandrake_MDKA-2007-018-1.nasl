
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24803);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2007:018-1: timezone");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2007:018-1 (timezone).");
 script_set_attribute(attribute: "description", value: "Updated timezone packages are being provided for older Mandriva Linux
systems that do not contain the new Daylight Savings Time information
for 2007 for certain time zones. These updated packages contain the
new information.
Update:
This update addresses timezone files such as Canada/Mountain that had
not been previously updated to the DST information. While files such
as MST7MDT were updated, the counterpart files such as Canada/Mountain
or America/Edmonton, etc. were not. This update addresses that and
also ensures that the new timezone information is copied over
/etc/localtime so no further configuration is required.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2007:018-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the timezone package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"timezone-2007c-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"timezone-2007c-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

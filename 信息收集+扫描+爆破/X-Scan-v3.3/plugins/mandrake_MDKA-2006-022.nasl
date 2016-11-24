
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24505);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2006:022: module-init-tools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2006:022 (module-init-tools).");
 script_set_attribute(attribute: "description", value: "The default configuration of module-init-tools was to send a HUP signal
to the CUPS daemon whenever the 'usblp' kernel module is loaded, for
example when a USB printer is plugged in. Due to udev also sending a HUP
signal to the CUPS daemon on pluggin in a USB printer there were two
HUPs one shortly after the other which often makes the CUPS daemon
crashing.
The updated module-init-tools package removes the usblp call
responsible for this bad behaviour.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2006:022");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the module-init-tools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"module-init-tools-3.2-0.pre8.2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

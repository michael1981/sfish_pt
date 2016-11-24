
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10861
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42827);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10861: asterisk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10861 (asterisk)");
 script_set_attribute(attribute: "description", value: "Asterisk is a complete PBX in software. It runs on Linux and provides
all of the features you would expect from a PBX and more. Asterisk
does voice over IP in three protocols, and can interoperate with
almost all standards-based telephony equipment using relatively
inexpensive hardware.

-
Update Information:


Update information :

* Tue Oct 27 2009 Jeffrey C. Ollie <jeff ocjtech us> - 1.6.1.8-1  - Update to
1.6.1.8 to fix bug 531199:  -  -
[9]http://downloads.asterisk.org/pub/security/AST-2009-007.html  -  - A missing
ACL
check for handling SIP INVITEs allows a device to make  - calls on networks
intended to be prohibited as defined by the 'deny'  - and 'permit' lines in
sip.conf. The ACL check for handling SIP  - registrations was not affected.
Other bugs were handled by previous updates, including them  here so that bodhi
will close them out.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the asterisk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"asterisk-1.6.1.8-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10475
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42270);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10475: slim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10475 (slim)");
 script_set_attribute(attribute: "description", value: "SLiM (Simple Login Manager) is a graphical login manager for X11.
It aims to be simple, fast and independent from the various
desktop environments.
SLiM is based on latest stable release of Login.app by Per LidÃ©n.

In the distribution, slim may be called through a wrapper, slim-dynwm,
which determines the available window managers using the freedesktop
information and modifies the slim configuration file accordingly,
before launching slim.

-
ChangeLog:


Update information :

* Sat Oct 10 2009 Lorenzo Villani <lvillani binaryhelix net> - 1.3.1-8
- Fix BZ #518068
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the slim package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"slim-1.3.1-8.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

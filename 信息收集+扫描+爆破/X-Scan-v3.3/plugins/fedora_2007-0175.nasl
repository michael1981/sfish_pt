
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0175
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27653);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-0175: zvbi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0175 (zvbi)");
 script_set_attribute(attribute: "description", value: "ZVBI provides functions to capture and decode VBI data. The vertical blanking
interval (VBI) is an interval in a television signal that temporarily suspends
transmission of the signal for the electron gun to move back up to the first
line of the television screen to trace the next screen field. The vertical
blanking interval can be used to carry data, since anything sent during the VBI
would naturally not be displayed; various test signals, closed captioning, and
other digital data can be sent during this time period.

-
Update Information:

contrib/ntsc-cc.c (CCdecode): Fixed a buffer overflow.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the zvbi package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"zvbi-0.2.25-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

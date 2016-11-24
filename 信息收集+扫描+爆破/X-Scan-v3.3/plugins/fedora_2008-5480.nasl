
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5480
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33370);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-5480: libetpan");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5480 (libetpan)");
 script_set_attribute(attribute: "description", value: "The purpose of this mail library is to provide a portable, efficient middleware
for different kinds of mail access. When using the drivers interface, the
interface is the same for all kinds of mail access, remote and local mailboxes.

-
Update Information:

Update to new upstream version 0.54 fixing a crash (NULL pointer dereference) i
n
the mail message header parser.    Note: There is no application in Fedora usin
g
libetpan library for which such crash could be considered a security issue. Thi
s
can only be a security sensitive issue for some 3rd party, not packages
applications.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the libetpan package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libetpan-0.54-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

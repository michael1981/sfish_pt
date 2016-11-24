
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3640
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38672);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 9 2009-3640: bash-completion");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3640 (bash-completion)");
 script_set_attribute(attribute: "description", value: "bash-completion is a collection of shell functions that take advantage
of the programmable completion feature of bash 2.

-
Update Information:

Update to version 1.0: [9]http://git.debian.org/?p=bash-completion/bash-
completion.git;a=blob;f=CHANGES;hb=28cdfc9243da41f5bdb29b7515482354c01438d3
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the bash-completion package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"bash-completion-1.0-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

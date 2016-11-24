
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2868
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31748);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-2868: mod_suphp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2868 (mod_suphp)");
 script_set_attribute(attribute: "description", value: "suPHP is an apache module for executing PHP scripts with the permissions of
their owners. It consists of an Apache module (mod_suphp) and a setuid root
binary (suphp) that is called by the Apache module to change the uid of the
process executing the PHP interpreter.

Please take a look at /usr/share/doc/mod_suphp-0.6.3/README.fedora for
installation instructions.

-
Update Information:

This update is a security update fixing two local privilege escalalation
problems.    mod_suphp 0.6.2 contains two race condition regarding symlink
checks. Using this attack vector a local attacker has the ability of changing
symlinks in the timeframe between the security check and the php execution
itself, leading suphp to execute code as another local user.    These have been
fixed in the 0.6.3 update with no further code changes being present making a
backport of the security fix unnecessary.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the mod_suphp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mod_suphp-0.6.3-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

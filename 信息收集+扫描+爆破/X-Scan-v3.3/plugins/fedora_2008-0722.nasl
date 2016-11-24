
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-0722
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29989);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2008-0722: python-paramiko");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-0722 (python-paramiko)");
 script_set_attribute(attribute: "description", value: "Paramiko (a combination of the esperanto words for 'paranoid' and 'friend') is
a module for python 2.3 or greater that implements the SSH2 protocol for secure
(encrypted and authenticated) connections to remote machines. Unlike SSL (aka
TLS), the SSH2 protocol does not require heirarchical certificates signed by a
powerful central authority. You may know SSH2 as the protocol that replaced
telnet and rsh for secure access to remote shells, but the protocol also
includes the ability to open arbitrary channels to remote services across an
encrypted tunnel. (This is how sftp works, for example.)

-
Update Information:

Apply patch to fix recently discovered security problem.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the python-paramiko package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"python-paramiko-1.7.1-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12339);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-287: vnc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-287");
 script_set_attribute(attribute: "description", value: '
  Updated VNC packages are available to fix a challenge replay attack that is
  present in the VNC server.

  VNC is a tool for providing a remote graphical user interface.

  The VNC DES authentication scheme is implemented using a challenge-response
  architecture, producing a random and different challenge for each
  authentication attempt.

  A bug in the function for generating the random challenge caused the random
  seed to be reset to the current time on every authentication attempt.
  As a result, two authentication attempts within the same second could
  receive the same challenge. An eavesdropper could exploit this
  vulnerability by replaying the response, thereby gaining authentication.

  All users of VNC are advised to upgrade to these errata packages, which
  contain an updated version and are not vulnerable to this issue.

  Note that when using VNC on an untrusted network, always make sure to
  tunnel the VNC protocol through a secure, authenticated channel such as
  SSH. Instructions on how to tunnel VNC through SSH are provided at the
  following URL: http://www.uk.research.att.com/vnc/sshvnc.html


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-287.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1336");
script_summary(english: "Check for the version of the vnc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vnc-3.3.3r2-18.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-doc-3.3.3r2-18.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vnc-server-3.3.3r2-18.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12365);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-055: rxvt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-055");
 script_set_attribute(attribute: "description", value: '
  Updated rxvt packages are available which fix a number of vulnerabilities
  in the handling of escape sequences.

  [Updated 12 March 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise
  Linux WS

  Rxvt is a color VT102 terminal emulator for the X Window System. A number
  of issues have been found in the escape sequence handling of Rxvt.
  These could be potentially exploited if an attacker can cause carefully
  crafted escape sequences to be displayed on an rxvt terminal being used by
  their victim.

  One of the features which most terminal emulators support is the ability
  for the shell to set the title of the window using an escape sequence.
  Certain xterm variants, including rxvt, also provide an escape sequence for
  reporting the current window title. This essentially takes the current
  title and places it directly on the command line. Since it is not
  possible to embed a carriage return into the window title itself, the
  attacker would have to convince the victim to press the Enter key for the
  title to be processed as a command, although the attacker can perform a
  number of actions to increase the likelihood of this happening.

  A certain escape sequence when displayed in rxvt will create an arbitrary
  file.

  It is possible to add malicious items to the dynamic menus through an
  escape sequence.

  Users of Rxvt are advised to upgrade to these errata packages which contain
  a patch to disable the title reporting functionality and patches to correct
  the other issues.

  Red Hat would like to thank H D Moore for bringing these issues to our
  attention.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-055.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0022", "CVE-2003-0023", "CVE-2003-0066");
script_summary(english: "Check for the version of the rxvt packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rxvt-2.7.8-4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

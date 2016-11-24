
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28236);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0701: xterm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0701");
 script_set_attribute(attribute: "description", value: '
  An updated xterm package that corrects a security issue is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red
  Hat Security Response Team.

  The xterm program is a terminal emulator for the X Window System. It
  provides DEC VT102 and Tektronix 4014 compatible terminals for
  programs that cannot use the window system directly.

  A bug was found in the way xterm packages were built that caused the
  pseudo-terminal device files of the xterm emulated terminals to be owned by
  the incorrect group. This flaw did not affect Red Hat Enterprise Linux 4
  Update 4 and earlier. (CVE-2007-2797)

  All users of xterm are advised to upgrade to this updated package, which
  contains a patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0701.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2797");
script_summary(english: "Check for the version of the xterm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xterm-192-8.el4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

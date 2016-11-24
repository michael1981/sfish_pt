
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25878);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0777: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0777");
 script_set_attribute(attribute: "description", value: '
  An updated gdm package that fixes a security issue is now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Gdm (the GNOME Display Manager) is a highly configurable reimplementation
  of xdm, the X Display Manager. Gdm allows you to log into your system with
  the X Window System running and supports running several different X
  sessions on your local machine at the same time.

  A flaw was found in the way Gdm listens on its unix domain socket. A local
  user could crash a running X session by writing malicious data to Gdm\'s
  unix domain socket. (CVE-2007-3381)

  All users of gdm should upgrade to this updated package, which contains a
  backported patch that resolves this issue.

  Red Hat would like to thank JLANTHEA for reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0777.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3381");
script_summary(english: "Check for the version of the gdm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gdm-2.16.0-31.0.1.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

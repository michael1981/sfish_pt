
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25145);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0286: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0286");
 script_set_attribute(attribute: "description", value: '
  An updated gdm package that fixes a security issue and a bug is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Gdm (the GNOME Display Manager) is a highly configurable reimplementation
  of xdm, the X Display Manager. Gdm allows you to log into your system with
  the X Window System running and supports running several different X
  sessions on your local machine at the same time.

  Marcus Meissner discovered a race condition issue in the way Gdm modifies
  the permissions on the .ICEauthority file. A local attacker could exploit
  this flaw to gain privileges. Due to the nature of the flaw, however, a
  successful exploitation was unlikely. (CVE-2006-1057)

  This erratum also includes a bug fix to correct the pam configuration for
  the audit system.

  All users of gdm should upgrade to this updated package, which contains
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0286.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-1057");
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

if ( rpm_check( reference:"gdm-2.6.0.5-7.rhel4.15", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

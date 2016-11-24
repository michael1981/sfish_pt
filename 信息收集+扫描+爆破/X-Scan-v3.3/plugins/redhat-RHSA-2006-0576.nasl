
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22111);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0576: kdebase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0576");
 script_set_attribute(attribute: "description", value: '
  Updated kdebase packages that resolve a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The kdebase packages provide the core applications for KDE, the K Desktop
  Environment.

  A flaw was found in KDE where the kdesktop_lock process sometimes
  failed to terminate properly. This issue could either block the user\'s
  ability to manually lock the desktop or prevent the screensaver to
  activate, both of which could have a security impact for users who rely on
  these functionalities.
  (CVE-2006-2933)

  Please note that this issue only affected Red Hat Enterprise Linux 3.

  All users of kdebase should upgrade to these updated packages, which
  contain a patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0576.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2933");
script_summary(english: "Check for the version of the kdebase packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdebase-3.1.3-5.11", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1.3-5.11", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

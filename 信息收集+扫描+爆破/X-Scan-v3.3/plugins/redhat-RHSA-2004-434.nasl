
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14802);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2004-434: redhat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-434");
 script_set_attribute(attribute: "description", value: '
  An updated redhat-config-nfs package that fixes bugs and potential security
  issues is now available for Red Hat Enterprise Linux 3.

  The redhat-config-nfs package includes a graphical user interface for
  creating, modifying, and deleting nfs shares.

  John Buswell discovered a flaw in redhat-config-nfs that could lead to
  incorrect permissions on exported shares when exporting to multiple
  hosts. This could cause an option such as "all_squash" to not be
  applied to all of the listed hosts. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0750 to
  this issue.

  Additionally, a bug was found that prevented redhat-config-nfs from being
  run if hosts didn\'t have options set in /etc/exports.

  All users of redhat-config-nfs are advised to upgrade to these updated
  packages as well as checking their NFS shares directly or via the
  /etc/exports file for any incorrectly set options.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-434.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0750");
script_summary(english: "Check for the version of the redhat packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"redhat-config-nfs-1.0.13-6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

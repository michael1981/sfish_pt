
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26907);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0951: nfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0951");
 script_set_attribute(attribute: "description", value: '
  An updated nfs-utils-lib package to correct two security flaws is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The nfs-utils-lib package contains support libraries that are needed by the
  commands and daemons of the nfs-utils package.

  The updated nfs-utils package fixes the following vulnerabilities:

  Tenable Network Security discovered a stack buffer overflow flaw in the RPC
  library used by nfs-utils-lib. A remote unauthenticated attacker who can
  access an application linked against nfs-utils-lib could trigger this flaw
  and cause the application to crash. On Red Hat Enterprise Linux 5 it is not
  possible to exploit this flaw to run arbitrary code as the overflow is
  blocked by FORTIFY_SOURCE. (CVE-2007-3999)

  Tony Ernst from SGI has discovered a flaw in the way nfsidmap maps NFSv4
  unknown uids. If an unknown user ID is encountered on an NFSv4 mounted
  filesystem, the files will default to being owned by \'root\' rather than
  \'nobody\'. (CVE-2007-4135)

  Users of nfs-utils-lib are advised to upgrade to this updated package,
  which contains backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0951.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3999", "CVE-2007-4135");
script_summary(english: "Check for the version of the nfs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nfs-utils-lib-1.0.8-7.2.z2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-lib-devel-1.0.8-7.2.z2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

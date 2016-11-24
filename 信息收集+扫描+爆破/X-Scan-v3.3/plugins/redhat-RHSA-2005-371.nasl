
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18278);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-371: ipxutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-371");
 script_set_attribute(attribute: "description", value: '
  An updated ncpfs package is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ncpfs is a file system that understands the Novell NetWare(TM) NCP
  protocol.

  A bug was found in the way ncpfs handled file permissions. ncpfs did not
  sufficiently check if the file owner matched the user attempting to access
  the file, potentially violating the file permissions. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0013 to this issue.

  All users of ncpfs are advised to upgrade to this updated package, which
  contains backported fixes for this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-371.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0013");
script_summary(english: "Check for the version of the ipxutils packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ipxutils-2.2.0.18-6.EL2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ncpfs-2.2.0.18-6.EL2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

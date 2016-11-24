
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12317);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-165: pxe");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-165");
 script_set_attribute(attribute: "description", value: '
  Updated PXE packages are now available for Red Hat Linux Advanced Server
  which fix a vulnerability that can crash the PXE server using certain
  DHCP packets.

  The PXE package contains the PXE (Preboot eXecution Environment)
  server and code needed for Linux to boot from a boot disk image on a
  Linux PXE server.

  It was found that the PXE server could be crashed using DHCP packets from
  some Voice Over IP (VOIP) phones. This bug could be used to cause a denial
  of service (DoS) attack on remote systems by using malicious packets.

  Users of PXE on Red Hat Linux Advanced Server are advised to upgrade to the
  new release which contains a version of PXE that is not vulnerable to this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-165.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0835");
script_summary(english: "Check for the version of the pxe packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pxe-0.1-31.99.7.3", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

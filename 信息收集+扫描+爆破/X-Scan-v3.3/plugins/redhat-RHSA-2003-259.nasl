
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12416);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-259: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-259");
 script_set_attribute(attribute: "description", value: '
  Updated GDM packages are available which correct a local crash if XDMCP is
  enabled.

  GDM is the GNOME Display Manager for X.

  Two bugs have been found in the X Display Manager Control Protocol (XDMCP)
  which could allow a denial of service attack (DoS) by crashing the gdm
  daemon. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CAN-2003-0548 and CAN-2003-0549 to these issues.

  This attack is only possible if XDMCP is enabled. XDMCP is not enabled by
  default in Red Hat Enterprise Linux distributions. In addition is
  documented best practise that XDMCP should only ever be run on trusted
  networks.

  Users of XDMCP in GDM should upgrade to these erratum packages which
  contain backported security fixes are are not vulnerable to these issues.

  Note that Red Hat Enterprise Linux 2.1 is not vulnerable to CAN-2003-0547,
  a vulnerability that allows a local user to read any text file, as it did
  not have the "examine session errors" feature.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-259.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0548", "CVE-2003-0549");
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

if ( rpm_check( reference:"gdm-2.2.3.1-20.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

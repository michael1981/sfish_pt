
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12437);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-386: freeradius");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-386");
 script_set_attribute(attribute: "description", value: '
  Updated FreeRADIUS packages are now available that fix a denial of service
  vulnerability.

  FreeRADIUS is an Internet authentication daemon, which implements the
  RADIUS protocol. It allows Network Access Servers (NAS boxes) to perform
  authentication for dial-up users.

  The rad_decode function in FreeRADIUS 0.9.2 and earlier allows remote
  attackers to cause a denial of service (crash) via a short RADIUS string
  attribute with a tag, which causes memcpy to be called with a -1 length
  argument, as demonstrated using the Tunnel-Password attribute. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0967 to this issue.

  Users of FreeRADIUS are advised to upgrade to these erratum packages
  containing FreeRADIUS 0.9.3 which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-386.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0967");
script_summary(english: "Check for the version of the freeradius packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freeradius-0.9.3-1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18512);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-512: gmc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-512");
 script_set_attribute(attribute: "description", value: '
  Updated mc packages that fix several security issues are now available for
  Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  Midnight Commander is a visual shell much like a file manager.

  Several denial of service bugs were found in Midnight Commander. These bugs
  could cause Midnight Commander to hang or crash if a victim opens a
  carefully crafted file. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CAN-2004-1009, CAN-2004-1090,
  CAN-2004-1091, CAN-2004-1093 and CAN-2004-1174 to these issues.

  A filename quoting bug was found in Midnight Commander\'s FISH protocol
  handler. If a victim connects via embedded SSH support to a host containing
  a carefully crafted filename, arbitrary code may be executed as the user
  running Midnight Commander. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-1175 to this issue.

  A buffer overflow bug was found in the way Midnight Commander handles
  directory completion. If a victim uses completion on a maliciously crafted
  directory path, it is possible for arbitrary code to be executed as the
  user running Midnight Commander. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-0763 to this issue.

  Users of mc are advised to upgrade to these packages, which contain
  backported security patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-512.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1093", "CVE-2004-1174", "CVE-2004-1175", "CVE-2005-0763");
script_summary(english: "Check for the version of the gmc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gmc-4.5.51-36.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.51-36.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mcserv-4.5.51-36.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

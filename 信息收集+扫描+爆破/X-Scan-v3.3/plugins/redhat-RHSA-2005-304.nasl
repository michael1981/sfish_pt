
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17644);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-304: grip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-304");
 script_set_attribute(attribute: "description", value: '
  A new grip package is available that fixes a remote buffer overflow.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  Grip is a GTK+ based front-end for CD rippers (such as cdparanoia and
  cdda2wav) and Ogg Vorbis encoders.

  Dean Brettle discovered a buffer overflow bug in the way grip handles data
  returned by CDDB servers. It is possible that if a user connects to a
  malicious CDDB server, an attacker could execute arbitrary code on the
  victim\'s machine. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0706 to this issue.

  Users of grip should upgrade to this updated package, which
  contains a backported patch, and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-304.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0706");
script_summary(english: "Check for the version of the grip packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"grip-2.96-1.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

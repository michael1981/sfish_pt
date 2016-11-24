
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15633);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-585: xchat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-585");
 script_set_attribute(attribute: "description", value: '
  An updated xchat package that fixes a stack buffer overflow in the SOCKSv5
  proxy code.

  X-Chat is a graphical IRC chat client for the X Window System.

  A stack buffer overflow has been fixed in the SOCKSv5 proxy code.
  An attacker could create a malicious SOCKSv5 proxy server in such a way
  that X-Chat would execute arbitrary code if a victim configured X-Chat to
  use the proxy. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0409 to this issue.

  Users of X-Chat should upgrade to this erratum package, which contains a
  backported security patch, and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-585.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0409");
script_summary(english: "Check for the version of the xchat packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xchat-1.8.9-1.21as.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xchat-2.0.4-4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

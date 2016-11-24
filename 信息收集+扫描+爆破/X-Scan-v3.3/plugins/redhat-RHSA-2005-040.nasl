
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17172);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-040: enscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-040");
 script_set_attribute(attribute: "description", value: '
  An updated enscript package that fixes several security issues is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GNU enscript converts ASCII files to PostScript.

  Enscript has the ability to interpret special escape sequences. A flaw was
  found in the handling of the epsf command used to insert inline EPS files
  into a document. An attacker could create a carefully crafted ASCII file
  which made use of the epsf pipe command in such a way that it could execute
  arbitrary commands if the file was opened with enscript by a victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-1184 to this issue.

  Additional flaws in Enscript were also discovered which can only be
  triggered by executing enscript with carefully crafted command line
  arguments. These flaws therefore only have a security impact if enscript
  is executed by other programs and passed untrusted data from remote users.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CAN-2004-1185 and CAN-2004-1186 to these issues.

  All users of enscript should upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-040.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
script_summary(english: "Check for the version of the enscript packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"enscript-1.6.1-28.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

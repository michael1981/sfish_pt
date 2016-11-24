
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(23684);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0742: elinks");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0742");
 script_set_attribute(attribute: "description", value: '
  An updated elinks package that corrects a security vulnerability is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Elinks is a text mode Web browser used from the command line that supports
  rendering modern web pages.

  An arbitrary file access flaw was found in the Elinks SMB protocol handler.
  A malicious web page could have caused Elinks to read or write files with
  the permissions of the user running Elinks. (CVE-2006-5925)

  All users of Elinks are advised to upgrade to this updated package, which
  resolves this issue by removing support for the SMB protocol from Elinks.

  Note: this issue did not affect the Elinks package shipped with Red Hat
  Enterprise Linux 3, or the Links package shipped with Red Hat Enterprise
  Linux 2.1.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0742.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5925");
script_summary(english: "Check for the version of the elinks packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"elinks-0.9.2-3.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12308);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2002-130: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-130");
 script_set_attribute(attribute: "description", value: '
  New Squid packages are available which fix various issues.

  Squid is a high-performance proxy caching server. The following summary
  describes the various issues found and fixed:

  Several buffer overflows have been found in the MSTN auth helper
  (msnt_auth) when configured to use denyusers or allowusers access control
  files.

  Several buffer overflows were found in the gopher client of Squid. It
  could be possible for a malicious gopher server to cause Squid to crash.

  A problem was found in the handling of the FTP data channel, possibly
  allowing abuse of the FTP proxy to bypass firewall rules or inject false
  FTP replies.

  Several possible buffer overflows were found in the code parsing FTP
  directories, which potentially allow for an untrusted FTP server to crash
  Squid.

  Thanks go to Olaf Kirch and the Squid team for notifying us of the
  problems and to the Squid team for providing patches.

  All users of Squid are advised to upgrade to these errata packages which
  contain patches to correct each of these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-130.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0713", "CVE-2002-0714", "CVE-2002-0715");
script_summary(english: "Check for the version of the squid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.4.STABLE6-6.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

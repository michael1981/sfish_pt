
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12303);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2002-124: xchat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-124");
 script_set_attribute(attribute: "description", value: '
  A security issue in XChat allows a malicious server to execute arbitrary
  commands.

  XChat is a popular cross-platform IRC client.

  Versions of XChat prior to 1.8.9 do not filter the response from an IRC
  server when a /dns query is executed. Because XChat resolves hostnames by
  passing the configured resolver and hostname to a shell, an IRC server may
  return a maliciously formatted response that executes arbitrary commands
  with the privileges of the user running XChat.

  All users of XChat are advised to update to these errata packages
  containing XChat version 1.8.9 which is not vulnerable to this issue.

  [update 14 Aug 2002]
  Previous packages pushed were not signed, this update replaces the packages
  with signed versions


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-124.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0382");
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

if ( rpm_check( reference:"xchat-1.8.9-1.21as.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

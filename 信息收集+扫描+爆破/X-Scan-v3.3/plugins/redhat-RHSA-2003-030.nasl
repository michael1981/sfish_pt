
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12357);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2003-030: lynx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-030");
 script_set_attribute(attribute: "description", value: '
  Updated Lynx packages fix an error in the way Lynx parses its command line
  arguments which can lead to faked headers being sent to a Web server.

  Lynx is a character-cell Web browser, suitable for running on terminals
  such as the VT100.

  Lynx constructs its HTTP queries from the command line (or WWW_HOME
  environment variable) without regard to special characters such as carriage
  returns or linefeeds. When given a URL containing such special characters,
  extra headers could be inserted into the request. This could cause scripts
  using Lynx to fetch data from the wrong site from servers with virtual
  hosting.

  Users of Lynx are advised to upgrade to these erratum packages which
  contain a patch to correct this isssue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-030.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1405");
script_summary(english: "Check for the version of the lynx packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lynx-2.8.4-18.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

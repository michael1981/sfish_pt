
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19672);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-358: exim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-358");
 script_set_attribute(attribute: "description", value: '
  Updated exim packages that fix a security issue in PCRE and a free space
  computation on large file system bug are now available for Red Hat
  Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Exim is a mail transport agent (MTA) developed at the University of
  Cambridge for use on Unix systems connected to the Internet.

  An integer overflow flaw was found in PCRE, a Perl-compatible regular
  expression library included within Exim. A local user could create a
  maliciously crafted regular expression in such as way that they could gain
  the privileges of the \'exim\' user. The Common Vulnerabilities and
  Exposures project assigned the name CAN-2005-2491 to this issue. These
  erratum packages change Exim to use the system PCRE library instead of the
  internal one.

  These packages also fix a minor flaw where the Exim Monitor was incorrectly
  computing free space on very large file systems.

  Users should upgrade to these erratum packages and also ensure they have
  updated the system PCRE library, for which erratum packages are available
  seperately in RHSA-2005:761


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-358.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2491");
script_summary(english: "Check for the version of the exim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"exim-4.43-1.RHEL4.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-doc-4.43-1.RHEL4.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-mon-4.43-1.RHEL4.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"exim-sa-4.43-1.RHEL4.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

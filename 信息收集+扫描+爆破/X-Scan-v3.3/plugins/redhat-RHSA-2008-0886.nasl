
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34191);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0886: libxml");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0886");
 script_set_attribute(attribute: "description", value: '
  Updated libxml2 packages that fix various security issues are now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The libxml2 packages provide a library that allows you to manipulate XML
  files. It includes support to read, modify, and write XML and HTML files.

  A heap-based buffer overflow flaw was found in the way libxml2 handled long
  XML entity names. If an application linked against libxml2 processed
  untrusted malformed XML content, it could cause the application to crash
  or, possibly, execute arbitrary code. (CVE-2008-3529)

  A denial of service flaw was found in the way libxml2 processed certain
  content. If an application linked against libxml2 processed malformed XML
  content, it could cause the application to use an excessive amount of CPU
  time and memory, and stop responding. (CVE-2003-1564)

  All users of libxml2 are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0886.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-1564", "CVE-2008-3529");
script_summary(english: "Check for the version of the libxml packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxml2-2.4.19-11.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.4.19-11.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.4.19-11.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

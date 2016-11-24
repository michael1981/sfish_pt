
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40543);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1205: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1205");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix multiple security issues and a bug are now
  available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server. The httpd package shipped
  with Red Hat Enterprise Linux 3 contains embedded copies of the Apache
  Portable Runtime (APR) libraries, which provide a free library of C data
  structures and routines, and also additional utility interfaces to support
  XML parsing, LDAP, database interfaces, URI parsing, and more.

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way the Apache Portable Runtime (APR) manages memory pool
  and relocatable memory allocations. An attacker could use these flaws to
  issue a specially-crafted request for memory allocation, which would lead
  to a denial of service (application crash) or, potentially, execute
  arbitrary code with the privileges of an application using the APR
  libraries. (CVE-2009-2412)

  A denial of service flaw was found in the Apache mod_deflate module. This
  module continued to compress large files until compression was complete,
  even if the network connection that requested the content was closed
  before compression completed. This would cause mod_deflate to consume
  large amounts of CPU if mod_deflate was enabled for a large file.
  (CVE-2009-1891)

  This update also fixes the following bug:

  * in some cases the Content-Length header was dropped from HEAD responses.
  This resulted in certain sites not working correctly with mod_proxy, such
  as www.windowsupdate.com. (BZ#506016)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1205.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1891", "CVE-2009-2412");
script_summary(english: "Check for the version of the httpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"httpd-2.0.46-75.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-75.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-75.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12374);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2003-081: zlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-081");
 script_set_attribute(attribute: "description", value: '
  Updated zlib packages that fix a buffer overflow vulnerability are now
  available.

  Zlib is a general-purpose, patent-free, lossless data compression
  library that is used by many different programs.

  The function gzprintf within zlib, when called with a string longer than
  Z_PRINTF_BUFZISE (= 4096 bytes), can overflow without giving a warning.

  zlib-1.1.4 and earlier exhibit this behavior. There are no known exploits
  of the gzprintf overrun, and only a few programs, including rpm2html
  and gimp-print, are known to use the gzprintf function.

  The problem has been fixed by checking the length of the output string
  within gzprintf.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-081.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0107");
script_summary(english: "Check for the version of the zlib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zlib-1.1.4-8.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.1.4-8.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

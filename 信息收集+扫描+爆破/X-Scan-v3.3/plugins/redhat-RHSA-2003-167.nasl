
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12395);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-167: lv");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-167");
 script_set_attribute(attribute: "description", value: '
  Updated lv packages that fix the possibility of local privilege escalation
  are now available.

  Lv is a powerful file viewer similar to less. It can decode and encode
  multilingual streams through many coding systems, such as ISO-8859,
  ISO-2022, EUC, SJIS Big5, HZ, and Unicode.

  A bug has been found in versions of lv that read a .lv file in the current
  working directory. Any user who subsequently runs lv in that directory
  and uses the v (edit) command can be forced to execute an arbitrary
  program.

  Users are advised to upgrade to these erratum packages, which contain a
  version of lv that is patched to read the .lv configuration file only in
  the user\'s home directory.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-167.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0188");
script_summary(english: "Check for the version of the lv packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lv-4.49.4-3.21AS.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

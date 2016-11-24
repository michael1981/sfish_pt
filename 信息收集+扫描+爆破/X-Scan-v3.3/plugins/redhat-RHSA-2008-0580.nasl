
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34953);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0580: vim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0580");
 script_set_attribute(attribute: "description", value: '
  Updated vim packages that fix security issues are now available for Red Hat
  Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  Vim (Visual editor IMproved) is an updated and improved version of the vi
  editor.

  Several input sanitization flaws were found in Vim\'s keyword and tag
  handling. If Vim looked up a document\'s maliciously crafted tag or keyword,
  it was possible to execute arbitrary code as the user running Vim.
  (CVE-2008-4101)

  Multiple security flaws were found in netrw.vim, the Vim plug-in providing
  file reading and writing over the network. If a user opened a specially
  crafted file or directory with the netrw plug-in, it could result in
  arbitrary code execution as the user running Vim. (CVE-2008-3076)

  A security flaw was found in zip.vim, the Vim plug-in that handles ZIP
  archive browsing. If a user opened a ZIP archive using the zip.vim plug-in,
  it could result in arbitrary code execution as the user running Vim.
  (CVE-2008-3075)

  A security flaw was found in tar.vim, the Vim plug-in which handles TAR
  archive browsing. If a user opened a TAR archive using the tar.vim plug-in,
  it could result in arbitrary code execution as the user runnin Vim.
  (CVE-2008-3074)

  Several input sanitization flaws were found in various Vim system
  functions. If a user opened a specially crafted file, it was possible to
  execute arbitrary code as the user running Vim. (CVE-2008-2712)

  Ulf H  rnhammar, of Secunia Research, discovered a format string flaw in
  Vim\'s help tag processor. If a user was tricked into executing the
  "helptags" command on malicious data, arbitrary code could be executed with
  the permissions of the user running Vim. (CVE-2007-2953)

  All Vim users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0580.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101");
script_summary(english: "Check for the version of the vim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vim-X11-7.0.109-4.el5_2.4z", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-common-7.0.109-4.el5_2.4z", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-7.0.109-4.el5_2.4z", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-7.0.109-4.el5_2.4z", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

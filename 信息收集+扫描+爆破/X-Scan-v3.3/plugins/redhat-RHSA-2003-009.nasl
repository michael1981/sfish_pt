#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12350);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1277");

 script_name(english:"RHSA-2003-009: WindowMaker");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2003-009");
 
 script_set_attribute(attribute:"description", value:
'
  Updated packages are available to fix a vulnerability in Window Maker.

  [Updated 06 Feb 2003]
  Fixed packages for Advanced Workstation 2.1 have been added.

  [Updated 31 Mar 2003]
  New erratum packages are available to fix a bug in the original security
  patch.

  [Updated 18 Jun 2003]
  The last update did not include the Advanced Workstation 2.1 packages,
  these have now been added back.

  Window Maker is an X11 window manager that emulates the look and feel
  of the NeXTSTEP graphical user interface.

  Al Viro found a buffer overflow in Window Maker 0.80.0 and earlier which
  may allow remote attackers to execute arbitrary code through a certain
  image file that is not properly handled when Window Maker uses width and
  height information to allocate a buffer. A user can exploit this
  vulnerability, for example, by opening a malicious theme.

  Users of Window Maker are advised to upgrade to these updated packages
  which contain a patch to correct this vulnerability.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-009.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the WindowMaker packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"WindowMaker-0.65.1-4.2", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-libs-0.65.1-4.2", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");

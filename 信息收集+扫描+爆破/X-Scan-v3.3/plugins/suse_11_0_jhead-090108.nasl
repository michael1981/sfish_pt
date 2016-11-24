
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40004);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  jhead (2009-01-08)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for jhead");
 script_set_attribute(attribute: "description", value: "This update of jhead fixes several security problems:
- CVE-2008-4575: buffer overflow in DoCommand()
- CVE-2008-4639: local symlink attack
- CVE-2008-4640: DoCommand() allowed deletion of arbitrary
  files
- CVE-2008-4641: execution of arbitrary shell commands in
  DoCommand()
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for jhead");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=435979");
script_end_attributes();

 script_cve_id("CVE-2008-4575", "CVE-2008-4639", "CVE-2008-4640", "CVE-2008-4641");
script_summary(english: "Check for the jhead package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"jhead-2.82-11.3", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"jhead-2.82-11.3", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

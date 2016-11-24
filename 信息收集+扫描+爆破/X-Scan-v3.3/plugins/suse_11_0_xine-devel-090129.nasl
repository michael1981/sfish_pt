
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40156);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  xine-devel (2009-01-29)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for xine-devel");
 script_set_attribute(attribute: "description", value: "This update of xine fixes multiple buffer overflows while
parsing files:
- CVE-2008-3231
- CVE-2008-5233
- CVE-2008-5234
- CVE-2008-5235
- CVE-2008-5236
- CVE-2008-5237
- CVE-2008-5238
- CVE-2008-5239
- CVE-2008-5240
- CVE-2008-5241
- CVE-2008-5242
- CVE-2008-5243
- CVE-2008-5244
- CVE-2008-5245
- CVE-2008-5246
- CVE-2008-5247
- CVE-2008-5248 These bugs can lead to remote code
  execution.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for xine-devel");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=417929");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=419541");
script_end_attributes();

 script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5235", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5238", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5242", "CVE-2008-5243", "CVE-2008-5244", "CVE-2008-5245", "CVE-2008-5246", "CVE-2008-5247", "CVE-2008-5248");
script_summary(english: "Check for the xine-devel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xine-devel-1.1.12-8.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xine-devel-1.1.12-8.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xine-extra-1.1.12-8.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xine-extra-1.1.12-8.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xine-lib-1.1.12-8.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xine-lib-1.1.12-8.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xine-lib-32bit-1.1.12-8.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

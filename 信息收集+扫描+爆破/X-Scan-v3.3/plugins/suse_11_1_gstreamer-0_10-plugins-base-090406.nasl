
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40226);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  gstreamer-0_10-plugins-base (2009-04-06)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for gstreamer-0_10-plugins-base");
 script_set_attribute(attribute: "description", value: "Specially crafted cover art tags in vorbis files could
trigger a heap overflow in the base64 decoder. Attackers
could potentially exploit that to execute arbitrary code
(CVE-2009-0586).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for gstreamer-0_10-plugins-base");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=481479");
script_end_attributes();

 script_cve_id("CVE-2009-0586");
script_summary(english: "Check for the gstreamer-0_10-plugins-base package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-0.10.21-2.21.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-32bit-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-devel-0.10.21-2.21.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-devel-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-doc-0.10.21-2.21.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-doc-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-lang-0.10.21-2.21.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gstreamer-0_10-plugins-base-lang-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libgstinterfaces-0_10-0-0.10.21-2.21.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libgstinterfaces-0_10-0-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libgstinterfaces-0_10-0-32bit-0.10.21-2.21.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

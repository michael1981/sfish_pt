
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40133);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  seamonkey (2009-06-17)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for seamonkey");
 script_set_attribute(attribute: "description", value: "The Mozilla Seamonkey browser suite was updated to version
1.1.16, fixing various bugs and security issues:

- Security update to 1.1.16
  * MFSA 2009-12/CVE-2009-1169 (bmo#460090,485217) Crash
    and remote code execution in XSL transformation
  * MFSA 2009-14/CVE-2009-1303/CVE-2009-1305 Crashes with
    evidence of memory corruption (rv:1.9.0.9)
- Security update  to 1.1.15
  * MFSA 2009-15/CVE-2009-0652 URL spoofing with box
    drawing character
  * MFSA 2009-07/CVE-2009-0771, CVE-2009-0772,
    CVE-2009-0773 CVE-2009-0774: Crashes with evidence of
    memory corruption (rv:1.9.0.7)
  * MFSA 2009-09/CVE-2009-0776: XML data theft via
    RDFXMLDataSource and cross-domain redirect
  * MFSA 2009-10/CVE-2009-0040: Upgrade PNG library to fix
    memory safety hazards
  * MFSA 2009-01/CVE-2009-0352 Crashes with evidence of
    memory corruption (rv:1.9.0.6)
  * MFSA 2009-05/CVE-2009-0357 XMLHttpRequest allows
    reading HTTPOnly cookies

Please note that the java openjdk plugin might not work
after installing this update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for seamonkey");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=488955");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=489411");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=492354");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478625");
script_end_attributes();

 script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0357", "CVE-2009-0652", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1169", "CVE-2009-1303", "CVE-2009-1305");
script_summary(english: "Check for the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.1.16-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-1.1.16-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.16-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.16-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.16-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.16-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.16-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.16-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.16-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.16-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.16-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.16-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

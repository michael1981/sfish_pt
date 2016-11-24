
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39462);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  seamonkey: Security update to version 1.1.16 (seamonkey-6310)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch seamonkey-6310");
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
script_set_attribute(attribute: "solution", value: "Install the security patch seamonkey-6310");
script_end_attributes();

script_cve_id("CVE-2009-1169", "CVE-2009-1303", "CVE-2009-1305", "CVE-2009-0652", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0357");
script_summary(english: "Check for the seamonkey-6310 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.1.16-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.16-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.16-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.16-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.16-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.16-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

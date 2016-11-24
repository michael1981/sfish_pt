
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27434);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  seamonkey: Security Update to version 1.0.2 (seamonkey-1671)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch seamonkey-1671");
 script_set_attribute(attribute: "description", value: "This security update fixes the following Problem in the 
Seamonkey suite:  MFSA 2006-40/CVE-2006-2781: Double-free 
vulnerability in Mozilla Thunderbird before 1.5.0.4 and 
SeaMonkey before 1.0.2 allows remote attackers to cause a 
denial of service (hang) and possibly execute arbitrary 
code via a VCard that contains invalid base64 characters.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch seamonkey-1671");
script_end_attributes();

script_cve_id("CVE-2006-2781");
script_summary(english: "Check for the seamonkey-1671 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-calendar-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.0.2-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

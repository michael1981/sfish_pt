
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27137);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  OpenOffice_org: Securityupdate to version 2.0.4.17 (OpenOffice_org-2682)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch OpenOffice_org-2682");
 script_set_attribute(attribute: "description", value: "Following security problems were fixed in OpenOffice_org:

This update also brings OpenOffice_org to version 2.0.4.17,
same as SUSE Linux Enterprise Desktop 10 and contains lots
of bugfixes.

CVE-2007-0002: Various problems were fixed in the
Wordperfect converter library libwpd in OpenOffice_org
which could be used by remote attackers to potentially
execute code or crash OpenOffice_org.

CVE-2007-0238: A stack overflow in the StarCalc parser
could be used by remote attackers to potentially execute
code by supplying a crafted document.

CVE-2007-0239: A shell quoting problem when opening URLs
was fixed which could be used by remote attackers to
execute code by supplying a crafted document and making the
user click on an embedded link.

Also support for the upcoming ODF - OfficeXML converter was
added.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch OpenOffice_org-2682");
script_end_attributes();

script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239");
script_summary(english: "Check for the OpenOffice_org-2682 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"OpenOffice_org-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-af-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-be-BY-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-bg-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cy-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-GB-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-galleries-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gu-IN-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hi-IN-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hr-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-km-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-lt-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-mk-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-mono-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nb-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nn-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-officebean-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pa-IN-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-BR-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-rw-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sr-CS-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-st-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ts-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-vi-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-xh-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zu-2.0.4-38.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29453);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for gtk2 (gtk2-2497)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gtk2-2497");
 script_set_attribute(attribute: "description", value: "A denial of service (crash) condition was fixed in the
image handling routines
 of GTK+. This could be triggered
for instance by viewing HTML emails or
 simiar
(CVE-2007-0010)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gtk2-2497");
script_end_attributes();

script_cve_id("CVE-2007-0010");
script_summary(english: "Check for the gtk2-2497 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"gtk2-2.8.10-39.22", release:"SLES10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.8.10-39.22", release:"SLES10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gtk2-doc-2.8.10-39.22", release:"SLES10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gtk2-2.8.10-39.22", release:"SLED10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.8.10-39.22", release:"SLED10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gtk2-doc-2.8.10-39.22", release:"SLED10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29429);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for KDE (fileshareset-4433)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch fileshareset-4433");
 script_set_attribute(attribute: "description", value: "Users could log in as root without having to enter the
password if auto login was enabled and if kdm was
configured to require the root passwort to shutdown the
system (CVE-2007-4569).


Javascript code could modify the URL in the address bar to
make the currently displayed web site appear to come from a
different site (CVE-2007-4224).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch fileshareset-4433");
script_end_attributes();

script_cve_id("CVE-2007-4224", "CVE-2007-4569");
script_summary(english: "Check for the fileshareset-4433 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"fileshareset-2.0-84.57", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-devel-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-extra-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-kdm-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-ksysguardd-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-nsplugin-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-samba-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-session-3.5.1-69.58", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.5.1-49.39", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-arts-3.5.1-49.39", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.5.1-49.39", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-doc-3.5.1-49.39", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"fileshareset-2.0-84.57", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-beagle-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-devel-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-kdm-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-ksysguardd-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-nsplugin-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-samba-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdebase3-session-3.5.1-69.58", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.5.1-49.39", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-arts-3.5.1-49.39", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.5.1-49.39", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-doc-3.5.1-49.39", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

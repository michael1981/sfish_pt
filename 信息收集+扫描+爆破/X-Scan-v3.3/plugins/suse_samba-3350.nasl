
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27430);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  samba security update (samba-3350)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch samba-3350");
 script_set_attribute(attribute: "description", value: "Specially crafted MS-RPC packets could overwrite heap
memory and therfore could potentially be exploited to
execute code (CVE-2007-2446).

Authenticated users could leverage specially crafted MS-RPC
packets to pass arguments unfiltered to /bin/sh
(CVE-2007-2447).

A bug in the local SID/Name translation routines may
potentially result in a user being able to issue SMB
protocol operations as root (CVE-2007-2444).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch samba-3350");
script_end_attributes();

script_cve_id("CVE-2007-2446", "CVE-2007-2447", "CVE-2007-2444");
script_summary(english: "Check for the samba-3350 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libmsrpc-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmsrpc-devel-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libsmbclient-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libsmbclient-32bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libsmbclient-64bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-32bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-64bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-32bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-64bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-python-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-32bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-64bit-3.0.23d-19.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

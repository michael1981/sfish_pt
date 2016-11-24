
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31624);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Kerberos 5 (krb5-5082)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch krb5-5082");
 script_set_attribute(attribute: "description", value: "This update fixes the following security bugs in
krb5/krb5-server: 
- CVE-2008-0062: null/dangling pointer (needs enabled krb4
  support) 
- CVE-2008-0063: possible operations on uninitialized
  buffer content/information leak (needs enabled krb4
  support) 
- CVE-2008-0947/CVE-2008-0948: out-of-bound array access in
  kadmind's RPC lib
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch krb5-5082");
script_end_attributes();

script_cve_id("CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947", "CVE-2008-0948");
script_summary(english: "Check for the krb5-5082 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"krb5-1.4.3-19.30.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-apps-clients-1.4.3-19.30.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-apps-servers-1.4.3-19.30.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-client-1.4.3-19.30.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.4.3-19.30.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-server-1.4.3-19.30.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-1.4.3-19.30.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-client-1.4.3-19.30.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.4.3-19.30.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

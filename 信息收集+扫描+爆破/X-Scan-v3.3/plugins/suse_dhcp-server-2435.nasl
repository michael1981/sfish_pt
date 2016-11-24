
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27196);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  dhcp-server: Securityfix for crashes triggered by LDAP server (dhcp-server-2435)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch dhcp-server-2435");
 script_set_attribute(attribute: "description", value: "A bug was fixed were a LDAP server with malicious data
providing information to the DHCP server could crash and
potentially execute code as the DHCP server.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch dhcp-server-2435");
script_end_attributes();

script_summary(english: "Check for the dhcp-server-2435 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"dhcp-server-3.0.3-23.10", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

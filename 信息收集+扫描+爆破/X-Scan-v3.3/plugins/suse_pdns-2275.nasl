
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27386);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  pdns: Securityupdate to fix denial of service problems (pdns-2275)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch pdns-2275");
 script_set_attribute(attribute: "description", value: "Two security problems that have been found in PowerDNS are
fixed by this update:

CVE-2006-4251: The PowerDNS Recursor can be made to crash
by sending malformed questions to it over TCP potentially
executing code.

CVE-2006-4252: Zero second CNAME TTLs can make PowerDNS
exhaust allocated stack space, and crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch pdns-2275");
script_end_attributes();

script_cve_id("CVE-2006-4251", "CVE-2006-4252");
script_summary(english: "Check for the pdns-2275 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"pdns-2.9.19-13.4", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

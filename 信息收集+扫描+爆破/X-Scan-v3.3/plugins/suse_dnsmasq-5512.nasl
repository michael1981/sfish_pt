
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33895);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  dnsmasq: random UDP ports and random TRXID (dnsmasq-5512)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch dnsmasq-5512");
 script_set_attribute(attribute: "description", value: "This update of dnsmasq uses random UDP source ports and a
random TRXID now. (CVE-2008-1447)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch dnsmasq-5512");
script_end_attributes();

script_cve_id("CVE-2008-1447");
script_summary(english: "Check for the dnsmasq-5512 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"dnsmasq-2.45-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

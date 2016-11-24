
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27160);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  avahi: Fixed securityproblem with netlink messages (avahi-2217)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch avahi-2217");
 script_set_attribute(attribute: "description", value: "Avahi did not check that the received netlink messages
originated from the kernel. This could be used by local
attackers to inject packets into avahi which could be used
to inject bad netlink messages into Avahi, confusing its
routing code or worse. (CVE-2006-5461)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch avahi-2217");
script_end_attributes();

script_cve_id("CVE-2006-5461");
script_summary(english: "Check for the avahi-2217 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"avahi-0.6.5-29.8", release:"SUSE10.1") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

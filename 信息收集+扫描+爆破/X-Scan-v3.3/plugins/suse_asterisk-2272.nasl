
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27156);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  asterisk: Security update to fix problems in CISCO SCCP and SIP channel driver. (asterisk-2272)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch asterisk-2272");
 script_set_attribute(attribute: "description", value: "This update fixes 2 security problem in the PBX software
Asterisk.

CVE-2006-5444: Integer overflow in the get_input function
in the Skinny channel driver (chan_skinny.c) as used by
Cisco SCCP phones, allows remote attackers to execute
arbitrary code via a certain dlen value that passes a
signed integer comparison and leads to a heap-based buffer
overflow.

CVE-2006-5445: A vulnerability in the SIP channel driver
(channels/chan_sip.c) in Asterisk on SUSE Linux 10.1 allows
remote attackers to cause a denial of service (resource
consumption) via unspecified vectors that result in the
creation of 'a real pvt structure' that uses more resources
than necessary.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch asterisk-2272");
script_end_attributes();

script_cve_id("CVE-2006-5444", "CVE-2006-5445");
script_summary(english: "Check for the asterisk-2272 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"asterisk-1.2.5-12.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

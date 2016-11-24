
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29421);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for ethereal (ethereal-3888)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ethereal-3888");
 script_set_attribute(attribute: "description", value: "Various security problems were fixed in the wireshark
0.99.6 release, which were backported to ethereal
(predecessor of wireshark):

CVE-2007-3389: Wireshark allowed remote attackers to cause
a denial of service (crash) via a crafted chunked encoding
in an HTTP response, possibly related to a zero-length
payload.

CVE-2007-3390: Wireshark when running on certain systems,
allowed remote attackers to cause a denial of service
(crash) via crafted iSeries capture files that trigger a
SIGTRAP.

CVE-2007-3391: Wireshark allowed remote attackers to cause
a denial of service (memory consumption) via a malformed
DCP ETSI packet that triggers an infinite loop.

CVE-2007-3392: Wireshark allowed remote attackers to cause
a denial of service via malformed (1) SSL or (2) MMS
packets that trigger an infinite loop.

CVE-2007-3393: Off-by-one error in the DHCP/BOOTP dissector
in Wireshark allowed remote attackers to cause a denial of
service (crash) via crafted DHCP-over-DOCSIS packets.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ethereal-3888");
script_end_attributes();

script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393");
script_summary(english: "Check for the ethereal-3888 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ethereal-0.10.14-16.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ethereal-devel-0.10.14-16.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.14-16.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

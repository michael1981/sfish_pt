
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27206);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  ethereal: Security update for denial of service in SSCOP dissector (ethereal-2029)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ethereal-2029");
 script_set_attribute(attribute: "description", value: "A security problem was fixed in ethereal, which could be
used by remote attackers to hang the ethereal process.

CVE-2006-4333: If the SSCOP dissector has a port range
configured AND the SSCOP payload protocol is Q.2931, a
malformed packet could make the Q.2931 dissector use up
available memory.  No port range is configured by default.

The vulnerabilities tracked by the Mitre CVE IDs
CVE-2006-4330 (SCSI dissector), CVE-2006-4331 (ESP
decryption), CVE-2006-4332 (DHCP dissector) do not affect
our shipped ethereal releases.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ethereal-2029");
script_end_attributes();

script_cve_id("CVE-2006-4333", "CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4332");
script_summary(english: "Check for the ethereal-2029 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ethereal-0.10.14-16.8", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ethereal-devel-0.10.14-16.8", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27387);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  perl-Net-DNS: security update (perl-Net-DNS-3961)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch perl-Net-DNS-3961");
 script_set_attribute(attribute: "description", value: "perl-Net-DNS used sequential IDs for DNS lookups which
could cause problem with some programs like spamassassin.
It potentially also simplified DNS spoofing attacks against
perl-Net-DNS (CVE-2007-3377).

Additionally malformed compressed DNS packets could trigger
an endless loop in perl-Net-DNS (CVE-2007-3409).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch perl-Net-DNS-3961");
script_end_attributes();

script_cve_id("CVE-2007-3377", "CVE-2007-3409");
script_summary(english: "Check for the perl-Net-DNS-3961 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-Net-DNS-0.59-18", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

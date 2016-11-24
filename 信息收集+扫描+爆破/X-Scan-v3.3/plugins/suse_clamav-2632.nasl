
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27178);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  clamav: security update to version 0.90 (clamav-2632)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-2632");
 script_set_attribute(attribute: "description", value: "This update to ClamAV version 0.90 fixes various bugs:

CVE-2007-0897: A filedescriptor leak in the handling of CAB
files can lead to a denial of service attack against the
clamd scanner daemon caused by remote attackers.

CVE-2007-0898: A directory traversal in handling of MIME
E-Mail headers could be used by remote attackers to
overwrite local files owned by the user under which clamd
is running.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-2632");
script_end_attributes();

script_cve_id("CVE-2007-0897", "CVE-2007-0898");
script_summary(english: "Check for the clamav-2632 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"clamav-0.90-0.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

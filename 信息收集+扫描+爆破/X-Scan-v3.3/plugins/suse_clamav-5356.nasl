
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33384);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  clamav: security update to 0.93.1 (clamav-5356)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-5356");
 script_set_attribute(attribute: "description", value: "This update brings clamav to version 0.93.1. It fixes
various bugs and one security issue:

CVE-2008-2713: libclamav/petite.c in ClamAV before 0.93.1
allows remote attackers to cause a denial of service via a
crafted Petite file that triggers an out-of-bounds read.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-5356");
script_end_attributes();

script_cve_id("CVE-2008-2713");
script_summary(english: "Check for the clamav-5356 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"clamav-0.93.1-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"clamav-db-0.93.1-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

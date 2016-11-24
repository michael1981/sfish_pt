
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27175);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  clamav: Security upgrade to version 0.88.5 (clamav-2180)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-2180");
 script_set_attribute(attribute: "description", value: "Two security problems have been found and fixed in the
antivirus scan engine 'clamav', which could be used by
remote attackers sending prepared E-Mails containing
special crafted infected files to potentially execute code.

CVE-2006-4182: A problem in dealing with PE (Portable
Executables aka Windows .EXE) files could result in an
integer overflow, causing a heap overflow, which could be
used by attackers to potentially execute code.

CVE-2006-5295: A problem in dealing with CHM (compressed
helpfile) exists that could cause an invalid memory read,
causing the clamav engine to crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-2180");
script_end_attributes();

script_cve_id("CVE-2006-4182", "CVE-2006-5295");
script_summary(english: "Check for the clamav-2180 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"clamav-0.88.5-0.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29397);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for clamav (clamav-2390)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-2390");
 script_set_attribute(attribute: "description", value: "This update to ClamAV version 0.88.7 fixes various bugs:

CVE-2006-5874: Clam AntiVirus (ClamAV) allows remote
attackers to cause a denial of service (crash) via a
malformed base64-encoded MIME attachment that triggers a
null pointer dereference.

CVE-2006-6481: Clam AntiVirus (ClamAV) 0.88.6 allowed
remote attackers to cause a denial of service (stack
overflow and application crash) by wrapping many layers of
multipart/mixed content around a document, a different
vulnerability than CVE-2006-5874 and CVE-2006-6406.

CVE-2006-6406: Clam AntiVirus (ClamAV) 0.88.6 allowed
remote attackers to bypass virus detection by inserting
invalid characters into base64 encoded content in a
multipart/mixed MIME file, as demonstrated with the EICAR
test file.


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-2390");
script_end_attributes();

script_cve_id("CVE-2006-5874", "CVE-2006-6406", "CVE-2006-6481");
script_summary(english: "Check for the clamav-2390 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"clamav-0.88.7-1.2", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

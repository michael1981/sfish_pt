
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27220);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  flash-player: Security upgrade to 7.0.69 (flash-player-2359)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch flash-player-2359");
 script_set_attribute(attribute: "description", value: "This security update brings the Adobe Flash Player to
version 7.0.69. It
 fixes the following security problem:

CVE-2006-5330: CRLF injection vulnerability in Adobe Flash
Player
 allows remote attackers to modify HTTP headers of
client requests
 and conduct HTTP Request Splitting attacks
via CRLF sequences in
 arguments to the ActionScript
functions (1) XML.addRequestHeader and (2)
XML.contentType. NOTE: the flexibility of the attack varies
depending
 on the type of web browser being used.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch flash-player-2359");
script_end_attributes();

script_cve_id("CVE-2006-5330");
script_summary(english: "Check for the flash-player-2359 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"flash-player-7.0.69.0-1.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

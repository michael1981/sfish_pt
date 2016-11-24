
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27344);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for mailman (mailman-2170)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mailman-2170");
 script_set_attribute(attribute: "description", value: "This update of mailman fixes the following security issues:
- A malicious user could visit a specially crafted URI and
  inject an apparent log message into Mailman's error log
  which might induce an unsuspecting administrator to visit
  a phishing site. This has been blocked. Thanks to Moritz
  Naumann for its discovery.
- Fixed denial of service attack which can be caused by
  some standards-breaking RFC 2231 formatted headers.
  CVE-2006-2941.
- Several cross-site scripting issues have been fixed.
  Thanks to Moritz Naumann for their discovery.
  CVE-2006-3636
- Fixed an unexploitable format string vulnerability.
  Discovery and fix by Karl Chen. Analysis of
  non-exploitability by Martin 'Joey' Schulze. Also thanks
  go to Lionel Elie Mamane. CVE-2006-2191.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch mailman-2170");
script_end_attributes();

script_cve_id("CVE-2006-2941", "CVE-2006-3636", "CVE-2006-2191");
script_summary(english: "Check for the mailman-2170 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mailman-2.1.7-15.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

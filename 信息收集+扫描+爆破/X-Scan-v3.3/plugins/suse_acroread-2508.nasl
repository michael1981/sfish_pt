
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29370);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for acroread (acroread-2508)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch acroread-2508");
 script_set_attribute(attribute: "description", value: "The Adobe Acrobat Reader has been updated to version 7.0.9.

This update also includes following security fixes:

CVE-2006-5857: A memory corruption problem was fixed in
Adobe Acrobat
 Reader can potentially lead to code
execution.

CVE-2007-0044: Universal Cross Site Request Forgery (CSRF)
problems
 were fixed in the Acrobat Reader plugin which
could be
 exploited by remote attackers to conduct CSRF
attacks
 using any site that is providing PDFs.

CVE-2007-0045: Cross site scripting problems in the Acrobat
Reader
 plugin were fixed, which could be exploited by
remote
 attackers to conduct XSS attacks against any site
that
 is providing PDFs.

CVE-2007-0046: A double free problem in the Acrobat Reader
plugin was fixed
 which could be used by remote attackers
to potentially execute
 arbitrary code.
 Note that all
platforms using Adobe Reader currently have
 counter
measures against such attack where it will just
 cause a
controlled abort().

CVE-2007-0047 and CVE-2007-0048 affect only Microsoft
Windows and
 Internet Explorer.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch acroread-2508");
script_end_attributes();

script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046", "CVE-2007-0047", "CVE-2007-0048");
script_summary(english: "Check for the acroread-2508 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"acroread-7.0.9-1.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

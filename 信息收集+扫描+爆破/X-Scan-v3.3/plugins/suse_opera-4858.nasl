
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29884);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Opera 9.25 security release (opera-4858)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opera-4858");
 script_set_attribute(attribute: "description", value: "Opera released version 9.25 of their browser to fix various
security problems.

CVE-2007-6520: Fixed an issue where plug-ins could be used
to allow cross domain scripting, as reported by David
Bloom. Details will be disclosed at a later date.

CVE-2007-6521: Fixed an issue with TLS certificates that
could be used to execute arbitrary code, as reported by
Alexander Klink (Cynops GmbH). Details will be disclosed at
a later date.

CVE-2007-6522: Rich text editing can no longer be used to
allow cross domain scripting, as reported by David Bloom.
See our advisory.

CVE-2007-6523: Fixed a problem where malformed BMP files
could cause Opera to temporarily freeze.

CVE-2007-6524: Prevented bitmaps from revealing random data
from memory, as reported by Gynvael Coldwind. Details will
be disclosed at a later date.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch opera-4858");
script_end_attributes();

script_cve_id("CVE-2007-6520", "CVE-2007-6521", "CVE-2007-6522", "CVE-2007-6523", "CVE-2007-6524");
script_summary(english: "Check for the opera-4858 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opera-9.25-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

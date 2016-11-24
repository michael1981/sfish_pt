
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27116);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox: Security update to 1.5.0.8 (MozillaFirefox-2251)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-2251");
 script_set_attribute(attribute: "description", value: "This update brings MozillaFirefox to the security update
release 1.5.0.8,  including the following security fixes.

Full details can be found on:
http://www.mozilla.org/projects/security/known-vulnerabiliti
es.html

MFSA2006-65: Is split into 3 sub-entries, for ongoing
stability improvements in the Mozilla browsers:
CVE-2006-5464: Layout engine flaws were fixed.
CVE-2006-5747: A xml.prototype.hasOwnProperty flaw was
fixed. CVE-2006-5748: Fixes were applied to the Javascript
engine.

MFSA2006-66/CVE-2006-5462: MFSA 2006-60 reported that RSA
digital signatures with a low exponent (typically 3) could
be forged. Firefox and Thunderbird 1.5.0.7, which
incorporated NSS version 3.10.2, were incompletely patched
and remained vulnerable to a variant of this attack.

MFSA2006-67/CVE-2006-5463: shutdown demonstrated that it
was possible to modify a Script object while it was
executing, potentially leading to the execution of
arbitrary JavaScript bytecode.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-2251");
script_end_attributes();

script_cve_id("CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748", "CVE-2006-5462", "CVE-2006-5463");
script_summary(english: "Check for the MozillaFirefox-2251 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-1.5.0.8-0.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.8-0.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

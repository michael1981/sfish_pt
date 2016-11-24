
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41011);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.1 Security Update:  MozillaThunderbird (2009-09-14)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaThunderbird");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird was updated to version 2.0.0.23.

The release fixes one security issue: MFSA 2009-42 /
CVE-2009-2408: IOActive security researcher Dan Kaminsky
reported a mismatch in the treatment of domain names in SSL
certificates between SSL clients and the Certificate
Authorities (CA) which issue server certificates. In
particular, if a malicious person requested a certificate
for a host name with an invalid null character in it most
CAs would issue the certificate if the requester owned the
domain specified after the null, while most SSL clients
(browsers) ignored that part of the name and used the
unvalidated part in front of the null. This made it
possible for attackers to obtain certificates that would
function for any site they wished to target. These
certificates could be used to intercept and potentially
alter encrypted communication between the client and a
server such as sensitive bank account transactions. This
vulnerability was independently reported to us by
researcher Moxie Marlinspike who also noted that since
Firefox relies on SSL to protect the integrity of security
updates this attack could be used to serve malicious
updates.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaThunderbird");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=534782");
script_end_attributes();

 script_cve_id("CVE-2009-2408");
script_summary(english: "Check for the MozillaThunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-2.0.0.23-0.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-2.0.0.23-0.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-devel-2.0.0.23-0.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-devel-2.0.0.23-0.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-2.0.0.23-0.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-2.0.0.23-0.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hunspell-1.2.7-1.28", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hunspell-1.2.7-1.35", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"hunspell-32bit-1.2.7-1.28", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

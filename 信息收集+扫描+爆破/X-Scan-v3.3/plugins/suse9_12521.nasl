
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42200);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for epiphany (12521)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12521");
 script_set_attribute(attribute: "description", value: 'seamonkey was updated to version 1.1.18, fixing various security issues:
MFSA 2009-43 / CVE-2009-2404
Moxie Marlinspike reported a heap overflow vulnerability in the code that
handles regular expressions in certificate names. This vulnerability could be
used to compromise the browser and run arbitrary code by presenting a specially
crafted certificate to the client. This code provided compatibility with the
non-standard regular expression syntax historically supported by Netscape
clients and servers. With version 3.5 Firefox switched to the more limited
industry-standard wildcard syntax instead and is not vulnerable to this flaw. 
MFSA 2009-42 / CVE-2009-2408:
IOActive security researcher Dan Kaminsky reported a mismatch in the treatment
of domain names in SSL certificates between SSL clients and the Certificate
Authorities (CA) which issue server certificates. In particular, if a malicious
person requested a certificate for a host name with an invalid null character
in it most CAs would issue the certificate if the requester owned the domain
specified after the null, while most SSL clients (browsers) ignored that part
of the name and used the unvalidated part in front of the null. This made it
possible for attackers to obtain certificates that would function for any site
they wished to target. These certificates could be used to intercept and
potentially alter encrypted communication between the client and a server such
as sensitive bank account transactions.
This vulnerability was independently reported to us by researcher Moxie
Marlinspike who also noted that since Firefox relies on SSL to protect the
integrity of security updates this attack could be used to serve malicious
updates. 
Mozilla would like to thank Dan and the Microsoft Vulnerability Research team
for coordinating a multiple-vendor response to this problem.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12521");
script_end_attributes();

script_cve_id("CVE-2009-2404","CVE-2009-2408");
script_summary(english: "Check for the security advisory #12521");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mozilla-1.8_seamonkey_1.1.18-0.1", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.8_seamonkey_1.1.18-0.1", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.8_seamonkey_1.1.18-0.1", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.8_seamonkey_1.1.18-0.1", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.8_seamonkey_1.1.18-0.1", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.8_seamonkey_1.1.18-0.1", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

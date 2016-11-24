# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(19742);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200509-10");
 script_cve_id("CVE-2005-2878");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-10
(Mailutils: Format string vulnerability in imap4d)


    The imap4d server contains a format string bug in the handling of IMAP
    SEARCH requests.
  
Impact

    An authenticated IMAP user could exploit the format string error in
    imap4d to execute arbitrary code as the imap4d user, which is usually
    root.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Mailutils users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailutils-0.6-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=303&type=vulnerabilities');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2878');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-10] Mailutils: Format string vulnerability in imap4d');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailutils: Format string vulnerability in imap4d');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/mailutils", unaffected: make_list("ge 0.6-r2"), vulnerable: make_list("lt 0.6-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

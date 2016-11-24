# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-04.xml
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
 script_id(21021);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200603-04");
 script_cve_id("CVE-2005-2661");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-04
(IMAP Proxy: Format string vulnerabilities)


    Steve Kemp discovered two format string errors in IMAP Proxy.
  
Impact

    A remote attacker could design a malicious IMAP server and entice
    someone to connect to it using IMAP Proxy, resulting in the execution
    of arbitrary code with the rights of the victim user.
  
Workaround

    Only connect to trusted IMAP servers using IMAP Proxy.
  
');
script_set_attribute(attribute:'solution', value: '
    All IMAP Proxy users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/up-imapproxy-1.2.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2661');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-04] IMAP Proxy: Format string vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IMAP Proxy: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/up-imapproxy", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

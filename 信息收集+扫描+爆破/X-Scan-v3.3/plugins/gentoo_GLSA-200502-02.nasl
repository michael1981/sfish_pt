# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-02.xml
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
 script_id(16439);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-02");
 script_cve_id("CVE-2005-0198");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-02
(UW IMAP: CRAM-MD5 authentication bypass)


    A logic bug in the code handling CRAM-MD5 authentication incorrectly
    specifies the condition for successful authentication.
  
Impact

    An attacker could exploit this vulnerability to authenticate as any
    mail user on a server with CRAM-MD5 authentication enabled.
  
Workaround

    Disable CRAM-MD5 authentication.
  
');
script_set_attribute(attribute:'solution', value: '
    All UW IMAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/uw-imap-2004b"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.kb.cert.org/vuls/id/702777');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0198');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-02] UW IMAP: CRAM-MD5 authentication bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UW IMAP: CRAM-MD5 authentication bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/uw-imap", unaffected: make_list("ge 2004b"), vulnerable: make_list("le 2004a")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

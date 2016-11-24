# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-05.xml
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
 script_id(16442);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-05");
 script_cve_id("CVE-2005-0101");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-05
(Newspost: Buffer overflow vulnerability)


    Niels Heinen has discovered a buffer overflow in the socket_getline()
    function of Newspost, which can be triggered by providing long strings
    that do not end with a newline character.
  
Impact

    A remote attacker could setup a malicious NNTP server and entice a
    Newspost user to post to it, leading to the crash of the Newspost
    process and potentially the execution of arbitrary code with the rights
    of the Newspost user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Newspost users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-nntp/newspost-2.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0101');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-05] Newspost: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Newspost: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-nntp/newspost", unaffected: make_list("rge 2.0-r1", "ge 2.1.1-r1"), vulnerable: make_list("lt 2.1.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

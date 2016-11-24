# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-31.xml
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
 script_id(14799);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200409-31");
 script_cve_id("CVE-2004-1378");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-31 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-31
(jabberd 1.x: Denial of Service vulnerability)


    Jose Antonio Calvo found a defect in routines handling XML parsing of
    incoming data. jabberd 1.x may crash upon reception of invalid data on
    any socket connection on which XML is parsed.
  
Impact

    A remote attacker may send a specific sequence of bytes to an open
    socket to crash the jabberd server, resulting in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All jabberd users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/jabberd-1.4.3-r4"
    # emerge ">=net-im/jabberd-1.4.3-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.jabber.org/pipermail/jabberd/2004-September/002004.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.jabber.org/pipermail/jadmin/2004-September/018046.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1378');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-31.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-31] jabberd 1.x: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'jabberd 1.x: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/jabberd", unaffected: make_list("ge 1.4.3-r4"), vulnerable: make_list("le 1.4.3-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

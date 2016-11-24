# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-09.xml
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
 script_id(19741);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200509-09");
 script_cve_id("CVE-2005-2875");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-09
(Py2Play: Remote execution of arbitrary Python code)


    Arc Riley discovered that Py2Play uses Python pickles to send objects
    over a peer-to-peer game network, and that clients accept without
    restriction the objects and code sent by peers.
  
Impact

    A remote attacker participating in a Py2Play-powered game can send
    malicious Python pickles, resulting in the execution of arbitrary
    Python code on the targeted game client.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All py2play users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/py2play-0.1.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2875');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-09] Py2Play: Remote execution of arbitrary Python code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Py2Play: Remote execution of arbitrary Python code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-python/py2play", unaffected: make_list("ge 0.1.8"), vulnerable: make_list("le 0.1.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-10.xml
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
 script_id(24722);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200702-10");
 script_cve_id("CVE-2006-3788", "CVE-2006-3789", "CVE-2006-3790", "CVE-2006-3791", "CVE-2006-3792");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-10
(UFO2000: Multiple vulnerabilities)


    Five vulnerabilities were found: a buffer overflow in recv_add_unit();
    a problem with improperly trusting user-supplied string information in
    decode_stringmap(); several issues with array manipulation via various
    commands during play; an SQL injection in server_protocol.cpp; and
    finally, a second buffer overflow in recv_map_data().
  
Impact

    An attacker could send crafted network traffic as part of a
    multi-player game that could result in remote code execution on the
    remote opponent or the server. A remote attacker could also run
    arbitrary SQL queries against the server account database, and perform
    a Denial of Service on a remote opponent by causing the game to crash.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    UFO2000 currently depends on the dumb-0.9.2 library, which has been
    removed from portage due to security problems (GLSA 200608-14) .
    Because of this, UFO2000 has been masked, and we recommend unmerging
    the package until the next beta release can remove the dependency on
    dumb.
    # emerge --ask --verbose --unmerge ufo2000
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3788');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3789');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3790');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3791');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3792');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-14.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-10] UFO2000: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UFO2000: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-strategy/ufo2000", unaffected: make_list("ge 0.7.1062"), vulnerable: make_list("lt 0.7.1062")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-18.xml
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
 script_id(18544);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200506-18");
 script_cve_id("CVE-2005-2050");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-18
(Tor: Information disclosure)


    A bug in Tor allows attackers to view arbitrary memory contents from an
    exit server\'s process space.
  
Impact

    A remote attacker could exploit the memory disclosure to gain sensitive
    information and possibly even private keys.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Tor users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/tor-0.0.9.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://archives.seul.org/or/announce/Jun-2005/msg00001.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2050');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-18] Tor: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tor: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/tor", unaffected: make_list("ge 0.0.9.10"), vulnerable: make_list("lt 0.0.9.10")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

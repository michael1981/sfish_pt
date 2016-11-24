# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-19.xml
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
 script_id(18383);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-19");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-19
(gxine: Format string vulnerability)


    Exworm discovered that gxine insecurely implements formatted
    printing in the hostname decoding function.
  
Impact

    A remote attacker could entice a user to open a carefully crafted
    file with gxine, possibly leading to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All gxine users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-video/gxine
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1692');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/13707');
script_set_attribute(attribute: 'see_also', value: 'http://www.0xbadexworm.org/adv/gxinefmt.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-19] gxine: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gxine: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/gxine", unaffected: make_list("rge 0.3.3-r2", "rge 0.4.1-r1", "ge 0.4.4"), vulnerable: make_list("lt 0.4.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

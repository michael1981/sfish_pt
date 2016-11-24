# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-14.xml
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
 script_id(18338);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200505-14");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-14
(Cheetah: Untrusted module search path)


    Brian Bird discovered that Cheetah searches for modules in the
    world-writable /tmp directory.
  
Impact

    A malicious local user could place a module containing arbitrary code
    in /tmp, which when imported would run with escalated privileges.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cheetah users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/cheetah-0.9.17_rc1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/15386/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-14] Cheetah: Untrusted module search path');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cheetah: Untrusted module search path');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-python/cheetah", unaffected: make_list("ge 0.9.17_rc1"), vulnerable: make_list("lt 0.9.17_rc1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

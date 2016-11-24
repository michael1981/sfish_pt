# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-18.xml
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
 script_id(16005);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200412-18");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-18
(abcm2ps: Buffer overflow vulnerability)


    Limin Wang has located a buffer overflow inside the put_words()
    function in the abcm2ps code.
  
Impact

    A remote attacker could convince the victim to download a
    specially-crafted ABC file. Upon execution, this file would trigger the
    buffer overflow and lead to the execution of arbitrary code with the
    permissions of the user running abcm2ps.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All abcm2ps users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/abcm2ps-3.7.21"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://moinejf.free.fr/abcm2ps-3.txt');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13523/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-18] abcm2ps: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'abcm2ps: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/abcm2ps", unaffected: make_list("ge 3.7.21"), vulnerable: make_list("lt 3.7.21")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

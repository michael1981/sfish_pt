# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-06.xml
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
 script_id(15933);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200412-06");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-06
(PHProjekt: setup.php vulnerability)


    Martin Muench, from it.sec, found a flaw in the setup.php file.
  
Impact

    Successful exploitation of the flaw allows a remote attacker
    without admin rights to make unauthorized changes to PHProjekt
    configuration.
  
Workaround

    As a workaround, you could replace the existing setup.php file in
    PHProjekt root directory by the one provided on the PHProjekt Advisory
    (see References).
  
');
script_set_attribute(attribute:'solution', value: '
    All PHProjekt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phprojekt-4.2-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.phprojekt.com/modules.php?op=modload&name=News&file=article&sid=189&mode=thread&order=0');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-06] PHProjekt: setup.php vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHProjekt: setup.php vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phprojekt", unaffected: make_list("ge 4.2-r1"), vulnerable: make_list("lt 4.2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

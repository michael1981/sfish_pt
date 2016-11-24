# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-27.xml
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
 script_id(16075);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200412-27");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-27
(PHProjekt: Remote code execution vulnerability)


    cYon discovered that the authform.inc.php script allows a remote
    user to define the global variable $path_pre.
  
Impact

    A remote attacker can exploit this vulnerability to force
    authform.inc.php to download and execute arbitrary PHP code with the
    privileges of the web server user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHProjekt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phprojekt-4.2-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.phprojekt.com/modules.php?op=modload&name=News&file=article&sid=193&mode=thread&order=0');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-27] PHProjekt: Remote code execution vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHProjekt: Remote code execution vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phprojekt", unaffected: make_list("ge 4.2-r2"), vulnerable: make_list("lt 4.2-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

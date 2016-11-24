# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-10.xml
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
 script_id(15971);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200412-10");
 script_cve_id("CVE-2004-1138");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-10
(Vim, gVim: Vulnerable options in modelines)


    Gentoo\'s Vim maintainer, Ciaran McCreesh, found several
    vulnerabilities related to the use of options in Vim modelines. Options
    like \'termcap\', \'printdevice\', \'titleold\', \'filetype\', \'syntax\',
    \'backupext\', \'keymap\', \'patchmode\' or \'langmenu\' could be abused.
  
Impact

    A local attacker could write a malicious file in a world readable
    location which, when opened in a modeline-enabled Vim, could trigger
    arbitrary commands with the rights of the user opening the file,
    resulting in privilege escalation. Please note that modelines are
    disabled by default in the /etc/vimrc file provided in Gentoo.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Vim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/vim-6.3-r2"
    All gVim users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/gvim-6.3-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1138');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-10] Vim, gVim: Vulnerable options in modelines');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Vim, gVim: Vulnerable options in modelines');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-editors/vim", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-editors/gvim", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

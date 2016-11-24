# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-22.xml
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
 script_id(18549);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200506-22");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-22
(sudo: Arbitrary command execution)


    The sudoers file is used to define the actions sudo users are
    permitted to perform. Charles Morris discovered that a specific layout
    of the sudoers file could cause the results of an internal check to be
    clobbered, leaving sudo vulnerable to a race condition.
  
Impact

    Successful exploitation would permit a local sudo user to execute
    arbitrary commands as another user.
  
Workaround

    Reorder the sudoers file using the visudo utility to ensure the
    \'ALL\' pseudo-command precedes other command definitions.
  
');
script_set_attribute(attribute:'solution', value: '
    All sudo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/sudo-1.6.8_p9"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.sudo.ws/sudo/alerts/path_race.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-22] sudo: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sudo: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/sudo", unaffected: make_list("ge 1.6.8_p9"), vulnerable: make_list("lt 1.6.8_p9")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

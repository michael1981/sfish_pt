# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-10.xml
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
 script_id(14669);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-10
(multi-gnome-terminal: Information leak)


    multi-gnome-terminal contains debugging code that has been known to output
    active keystrokes to a potentially unsafe location. Output has been seen to
    show up in the \'.xsession-errors\' file in the users home directory. Since
    this file is world-readable on many machines, this bug has the potential to
    leak sensitive information to anyone using the system.
  
Impact

    Any authorized user on the local machine has the ability to read any
    critical data that has been entered into the terminal, including passwords.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All multi-gnome-terminal users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-terms/multi-gnome-terminal-1.6.2-r1"
    # emerge ">=x11-terms/multi-gnome-terminal-1.6.2-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-10] multi-gnome-terminal: Information leak');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'multi-gnome-terminal: Information leak');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-terms/multi-gnome-terminal", unaffected: make_list("ge 1.6.2-r1"), vulnerable: make_list("lt 1.6.2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

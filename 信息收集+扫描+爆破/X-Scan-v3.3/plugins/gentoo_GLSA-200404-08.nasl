# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-08.xml
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
 script_id(14473);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200404-08");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-08
(GNU Automake symbolic link vulnerability)


    Automake may be vulnerable to a symbolic link attack which may allow an
    attacker to modify data or escalate their privileges. This is due to
    the insecure way Automake creates directories during compilation. An
    attacker may be able to create symbolic links in the place of files
    contained in the affected directories, which may potentially lead to
    elevated privileges due to modification of data.
  
Impact

    An attacker may be able to use this vulnerability to modify data in an
    unauthorized fashion or elevate their privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    Automake users should upgrade to the latest versions:
    # emerge --sync
    # emerge --ask --oneshot --verbose sys-devel/automake
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-08] GNU Automake symbolic link vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU Automake symbolic link vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-devel/automake", unaffected: make_list("ge 1.8.5-r3", "rge 1.7.9-r1", "lt 1.7"), vulnerable: make_list("le 1.8.5-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

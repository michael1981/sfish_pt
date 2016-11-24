# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-14.xml
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
 script_id(21707);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200606-14");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-14
(GDM: Privilege escalation)


    GDM allows a normal user to access the configuration manager.
  
Impact

    When the "face browser" in GDM is enabled, a normal user can use the
    "configure login manager" with his/her own password instead of the root
    password, and thus gain additional privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GDM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=gnome-base/gdm-2.8.0.8"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://bugzilla.gnome.org/show_bug.cgi?id=343476');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2452');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-14] GDM: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GDM: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "gnome-base/gdm", unaffected: make_list("ge 2.8.0.8"), vulnerable: make_list("lt 2.8.0.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

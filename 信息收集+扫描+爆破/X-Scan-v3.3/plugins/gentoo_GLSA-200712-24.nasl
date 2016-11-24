# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-24.xml
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
 script_id(29821);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-24");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-24
(AMD64 x86 emulation GTK+ library: User-assisted execution of arbitrary code)


    The Cairo versions used by the AMD64 x86 emulation GTK+ libraries were
    vulnerable to integer overflow vulnerabilities (GLSA 200712-04).
  
Impact

    A remote attacker could entice a user to view or process a specially
    crafted PNG image file in an application linked against Cairo, possibly
    leading to the execution of arbitrary code with the privileges of the
    user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All AMD64 x86 emulation GTK+ library users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-gtklibs-20071214"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-04.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-24] AMD64 x86 emulation GTK+ library: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AMD64 x86 emulation GTK+ library: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/emul-linux-x86-gtklibs", arch: "amd64", unaffected: make_list("ge 20071214"), vulnerable: make_list("lt 20071214")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

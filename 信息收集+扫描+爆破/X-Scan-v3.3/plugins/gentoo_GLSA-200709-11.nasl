# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-11.xml
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
 script_id(26101);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-11");
 script_cve_id("CVE-2007-3381");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-11
(GDM: Local Denial of Service)


    The result of a g_strsplit() call is incorrectly parsed in the files
    daemon/gdm.c, daemon/gdmconfig.c, gui/gdmconfig.c and
    gui/gdmflexiserver.c, allowing for a null pointer dereference.
  
Impact

    A local user could send a crafted message to /tmp/.gdm_socket that
    would trigger the null pointer dereference and crash GDM, thus
    preventing it from managing future displays.
  
Workaround

    Restrict the write permissions on /tmp/.gdm_socket to trusted users
    only after each GDM restart.
  
');
script_set_attribute(attribute:'solution', value: '
    All GDM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "gnome-base/gdm"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:S/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3381');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-11] GDM: Local Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GDM: Local Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "gnome-base/gdm", unaffected: make_list("ge 2.18.4", "rge 2.16.7"), vulnerable: make_list("lt 2.18.4")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");

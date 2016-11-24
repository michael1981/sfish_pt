# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-10.xml
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
 script_id(14521);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200406-10");
 script_cve_id("CVE-2004-0522");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-10
(Gallery: Privilege escalation vulnerability)


    There is a vulnerability in the Gallery photo album software which may
    allow an attacker to gain administrator privileges within Gallery. A
    Gallery administrator has full access to all albums and photos on the
    server, thus attackers may add or delete photos at will.
  
Impact

    Attackers may gain full access to all Gallery albums. There is no risk
    to the webserver itself, or the server on which it runs.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version of Gallery.
    # emerge sync
    # emerge -pv ">=www-apps/gallery-1.4.3_p2"
    # emerge ">=www-apps/gallery-1.4.3_p2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=123&mode=thread&order=0&thold=0');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0522');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-10] Gallery: Privilege escalation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 1.4.3_p2"), vulnerable: make_list("le 1.4.3_p1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

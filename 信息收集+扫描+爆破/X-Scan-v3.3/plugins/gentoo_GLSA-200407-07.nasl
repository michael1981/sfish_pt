# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-07.xml
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
 script_id(14540);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200407-07");
 script_cve_id("CVE-2004-0647");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-07
(Shorewall : Insecure temp file handling)


    Shorewall uses temporary files and directories in an insecure manner. A
    local user could create symbolic links at specific locations,
    eventually overwriting other files on the filesystem with the rights of
    the shorewall process.
  
Impact

    An attacker could exploit this vulnerability to overwrite arbitrary
    system files with root privileges, resulting in Denial of Service or
    further exploitation.
  
Workaround

    There is no known workaround at this time. All users should upgrade to
    the latest available version of Shorewall.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version of Shorewall,
    as follows:
    # emerge sync
    # emerge -pv ">=net-firewall/shorewall-1.4.10f"
    # emerge ">=net-firewall/shorewall-1.4.10f"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://lists.shorewall.net/pipermail/shorewall-announce/2004-June/000385.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0647');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-07] Shorewall : Insecure temp file handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Shorewall : Insecure temp file handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/shorewall", unaffected: make_list("ge 1.4.10f"), vulnerable: make_list("le 1.4.10c")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

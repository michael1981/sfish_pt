# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-17.xml
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
 script_id(20358);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-17");
 script_cve_id("CVE-2005-4532", "CVE-2005-4533");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-17
(scponly: Multiple privilege escalation issues)


    Max Vozeler discovered that the scponlyc command allows users to chroot
    into arbitrary directories. Furthermore, Pekka Pessi reported that
    scponly insufficiently validates command-line parameters to a scp or
    rsync command.
  
Impact

    A local attacker could gain root privileges by chrooting into arbitrary
    directories containing hardlinks to setuid programs. A remote scponly
    user could also send malicious parameters to a scp or rsync command
    that would allow to escape the shell restrictions and execute arbitrary
    programs.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All scponly users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/scponly-4.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://sublimation.org/scponly/index.html#relnotes');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4532');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4533');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-17] scponly: Multiple privilege escalation issues');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'scponly: Multiple privilege escalation issues');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/scponly", unaffected: make_list("ge 4.2"), vulnerable: make_list("lt 4.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

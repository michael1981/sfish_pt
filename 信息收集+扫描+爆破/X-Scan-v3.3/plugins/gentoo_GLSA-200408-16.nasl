# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-16.xml
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
 script_id(14572);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-16");
 script_cve_id("CVE-2004-1453");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-16
(glibc: Information leak with LD_DEBUG)


    Silvio Cesare discovered a potential information leak in glibc. It
    allows LD_DEBUG on SUID binaries where it should not be allowed. This
    has various security implications, which may be used to gain
    confidentional information.
  
Impact

    An attacker can gain the list of symbols a SUID application uses and
    their locations and can then use a trojaned library taking precendence
    over those symbols to gain information or perform further exploitation.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of glibc.
  
');
script_set_attribute(attribute:'solution', value: '
    All glibc users should upgrade to the latest version:
    # emerge sync
    # emerge -pv your_version
    # emerge your_version
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1453');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-16] glibc: Information leak with LD_DEBUG');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'glibc: Information leak with LD_DEBUG');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-libs/glibc", arch: "ppc64", unaffected: make_list("ge 2.3.4.20040808"), vulnerable: make_list("le 2.3.4.20040605")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");

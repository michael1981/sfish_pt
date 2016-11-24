# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-15.xml
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
 script_id(25236);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-15");
 script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-15
(Samba: Multiple vulnerabilities)


    Samba contains a logical error in the smbd daemon when translating
    local SID to user names (CVE-2007-2444). Furthermore, Samba contains
    several bugs when parsing NDR encoded RPC parameters (CVE-2007-2446).
    Lastly, Samba fails to properly sanitize remote procedure input
    provided via Microsoft Remote Procedure Calls (CVE-2007-2447).
  
Impact

    A remote attacker could exploit these vulnerabilities to gain root
    privileges via various vectors.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.24-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2444');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2446');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2447');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-15] Samba: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.24-r2"), vulnerable: make_list("lt 3.0.24-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

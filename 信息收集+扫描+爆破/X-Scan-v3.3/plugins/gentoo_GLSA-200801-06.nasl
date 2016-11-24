# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-06.xml
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
 script_id(29910);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200801-06");
 script_cve_id("CVE-2007-6531", "CVE-2007-6532");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-06
(Xfce: Multiple vulnerabilities)


    Gregory Andersen reported that the Xfce4 panel does not correctly
    calculate memory boundaries, leading to a stack-based buffer overflow
    in the launcher_update_panel_entry() function (CVE-2007-6531). Daichi
    Kawahata reported libxfcegui4 did not copy provided values when
    creating "SessionClient" structs, possibly leading to access of freed
    memory areas (CVE-2007-6532).
  
Impact

    A remote attacker could entice a user to install a specially crafted
    "rc" file to execute arbitrary code via long strings in the "Name" and
    "Comment" fields or via unspecified vectors involving the second
    vulnerability.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xfce4 panel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=xfce-base/xfce4-panel-4.4.2"
    All libxfcegui4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=xfce-base/libxfcegui4-4.4.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6531');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6532');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-06] Xfce: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xfce: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "xfce-base/libxfcegui4", unaffected: make_list("ge 4.4.2"), vulnerable: make_list("lt 4.4.2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "xfce-base/xfce4-panel", unaffected: make_list("ge 4.4.2"), vulnerable: make_list("lt 4.4.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

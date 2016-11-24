# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-01.xml
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
 script_id(25866);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200708-01");
 script_cve_id("CVE-2007-2022", "CVE-2007-3456", "CVE-2007-3457");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-01
(Macromedia Flash Player: Remote arbitrary code execution)


    Mark Hills discovered some errors when interacting with a browser for
    keystrokes handling (CVE-2007-2022). Stefano Di Paola and Giorgio Fedon
    from Minded Security discovered a boundary error when processing FLV
    files (CVE-2007-3456). An input validation error when processing HTTP
    referrers has also been reported (CVE-2007-3457).
  
Impact

    A remote attacker could entice a user to open a specially crafted file,
    possibly leading to the execution of arbitrary code with the privileges
    of the user running the Macromedia Flash Player, or sensitive data
    access.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Macromedia Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-plugins/adobe-flash-9.0.48.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2022');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3456');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3457');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-01] Macromedia Flash Player: Remote arbitrary code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Macromedia Flash Player: Remote arbitrary code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-plugins/adobe-flash", unaffected: make_list("ge 9.0.48.0"), vulnerable: make_list("lt 9.0.48.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

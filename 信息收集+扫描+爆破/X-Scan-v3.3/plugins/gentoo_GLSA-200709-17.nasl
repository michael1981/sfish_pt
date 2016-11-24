# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-17.xml
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
 script_id(26215);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-17");
 script_cve_id("CVE-2007-0650", "CVE-2007-3387");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-17
(teTeX: Multiple buffer overflows)


    Mark Richters discovered a buffer overflow in the open_sty() function
    in file mkind.c. Other vulnerabilities have also been discovered in the
    same file but might not be exploitable (CVE-2007-0650). Tetex also
    includes vulnerable code from GD library (GLSA 200708-05), and from
    Xpdf (CVE-2007-3387).
  
Impact

    A remote attacker could entice a user to process a specially crafted
    PNG, GIF or PDF file, or to execute "makeindex" on an overly long
    filename. In both cases, this could lead to the remote execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All teTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/tetex-3.0_p1-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0650');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3387');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-17] teTeX: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'teTeX: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/tetex", unaffected: make_list("ge 3.0_p1-r4"), vulnerable: make_list("lt 3.0_p1-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

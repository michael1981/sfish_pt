# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-02.xml
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
 script_id(21195);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200604-02");
 script_cve_id("CVE-2006-1260", "CVE-2006-1491");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200604-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200604-02
(Horde Application Framework: Remote code execution)


    Jan Schneider of the Horde team discovered a vulnerability in the
    help viewer of the Horde Application Framework that could allow remote
    code execution (CVE-2006-1491). Paul Craig reported that
    "services/go.php" fails to validate the passed URL parameter correctly
    (CVE-2006-1260).
  
Impact

    An attacker could exploit the vulnerability in the help viewer to
    execute arbitrary code with the privileges of the web server user. By
    embedding a NULL character in the URL parameter, an attacker could
    exploit the input validation issue in go.php to read arbitrary files.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde Application Framework users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-3.1.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1260');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1491');
script_set_attribute(attribute: 'see_also', value: 'http://lists.horde.org/archives/announce/2006/000271.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200604-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200604-02] Horde Application Framework: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Application Framework: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 3.1.1"), vulnerable: make_list("lt 3.1.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

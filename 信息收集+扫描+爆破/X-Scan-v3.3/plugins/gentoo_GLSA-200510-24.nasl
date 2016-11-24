# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-24.xml
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
 script_id(20117);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200510-24");
 script_cve_id("CVE-2005-3335", "CVE-2005-3336", "CVE-2005-3337", "CVE-2005-3338", "CVE-2005-3339");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-24
(Mantis: Multiple vulnerabilities)


    Mantis contains several vulnerabilities, including:
    a remote file inclusion vulnerability
    an SQL injection vulnerability
    multiple cross site scripting vulnerabilities
    multiple information disclosure vulnerabilities
  
Impact

    An attacker could exploit the remote file inclusion vulnerability to
    execute arbitrary script code, and the SQL injection vulnerability to
    access or modify sensitive information from the Mantis database.
    Furthermore the cross-site scripting issues give an attacker the
    ability to inject and execute malicious script code or to steal
    cookie-based authentication credentials, potentially compromising the
    victim\'s browser. An attacker could exploit other vulnerabilities to
    disclose information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mantis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mantisbt-0.19.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.mantisbt.org/changelog.php');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3335');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3336');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3337');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3338');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3339');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-24] Mantis: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mantis: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/mantisbt", unaffected: make_list("ge 0.19.3"), vulnerable: make_list("lt 0.19.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

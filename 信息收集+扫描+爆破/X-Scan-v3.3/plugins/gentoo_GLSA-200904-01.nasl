# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-01.xml
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
 script_id(36078);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200904-01");
 script_cve_id("CVE-2008-6508", "CVE-2008-6509", "CVE-2008-6510", "CVE-2008-6511", "CVE-2009-0496", "CVE-2009-0497");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-01
(Openfire: Multiple vulnerabilities)


    Two vulnerabilities have been reported by Federico Muttis, from CORE
    IMPACT\'s Exploit Writing Team:
    Multiple missing or incomplete input validations in several .jsps
    (CVE-2009-0496).
    Incorrect input validation of the "log" parameter in log.jsp
    (CVE-2009-0497).
    Multiple vulnerabilities have been reported by Andreas Kurtz:
    Erroneous built-in exceptions to input validation in login.jsp
    (CVE-2008-6508).
    Unsanitized user input to the "type" parameter in
    sipark-log-summary.jsp used in SQL statement. (CVE-2008-6509)
    A Cross-Site-Scripting vulnerability due to unsanitized input to the
    "url" parameter. (CVE-2008-6510, CVE-2008-6511)
  
Impact

    A remote attacker could execute arbitrary code on clients\' systems by
    uploading a specially crafted plugin, bypassing authentication.
    Additionally, an attacker could read arbitrary files on the server or
    execute arbitrary SQL statements. Depending on the server\'s
    configuration the attacker might also execute code on the server via an
    SQL injection.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Openfire users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/openfire-3.6.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6508');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6509');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6510');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6511');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0496');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0497');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-01] Openfire: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Openfire: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/openfire", unaffected: make_list("ge 3.6.3"), vulnerable: make_list("lt 3.6.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

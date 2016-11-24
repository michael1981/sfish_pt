# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-17.xml
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
 script_id(16458);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-17");
 script_cve_id("CVE-2004-1157", "CVE-2004-1489", "CVE-2004-1490", "CVE-2004-1491", "CVE-2005-0456", "CVE-2005-0457");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-17
(Opera: Multiple vulnerabilities)


    Opera contains several vulnerabilities:
    fails to properly validate Content-Type and filename.
    fails to properly validate date: URIs.
    uses kfmclient exec as the Default Application to handle downloaded
    files when integrated with KDE.
    fails to properly control frames.
    uses Sun Java packages insecurely.
    searches an insecure path for plugins.
  
Impact

    An attacker could exploit these vulnerabilities to:
    execute arbitrary code.
    load a malicious frame in the context of another browser
    session.
    leak information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-7.54-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/linux/changelogs/754u1/');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/linux/changelogs/754u2/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1157');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1489');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1490');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1491');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0456');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0457');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-17] Opera: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 7.54-r3"), vulnerable: make_list("lt 7.54-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

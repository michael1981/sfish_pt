# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-15.xml
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
 script_id(19535);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200508-15");
 script_cve_id("CVE-2005-2728");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-15
(Apache 2.0: Denial of Service vulnerability)


    Filip Sneppe discovered that Apache improperly handles byterange
    requests to CGI scripts.
  
Impact

    A remote attacker may access vulnerable scripts in a malicious way,
    exhausting all RAM and swap space on the server, resulting in a Denial
    of Service of the Apache server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.0.54-r9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://issues.apache.org/bugzilla/show_bug.cgi?id=29962');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2728');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-15] Apache 2.0: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2.0: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.0.54-r9", "lt 2.0"), vulnerable: make_list("lt 2.0.54-r9")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

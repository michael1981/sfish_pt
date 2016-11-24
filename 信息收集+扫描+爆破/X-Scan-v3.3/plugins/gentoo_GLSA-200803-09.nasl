# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-09.xml
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
 script_id(31384);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-09");
 script_cve_id("CVE-2008-1080", "CVE-2008-1081", "CVE-2008-1082");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-09
(Opera: Multiple vulnerabilities)


    Mozilla discovered that Opera does not handle input to file form fields
    properly, allowing scripts to manipulate the file path (CVE-2008-1080).
    Max Leonov found out that image comments might be treated as scripts,
    and run within the wrong security context (CVE-2008-1081). Arnaud
    reported that a wrong representation of DOM attribute values of
    imported XML documents allows them to bypass sanitization filters
    (CVE-2008-1082).
  
Impact

    A remote attacker could entice a user to upload a file with a known
    path by entering text into a specially crafted form, to execute scripts
    outside intended security boundaries and conduct Cross-Site Scripting
    attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.26"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1080');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1081');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1082');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-09] Opera: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.26"), vulnerable: make_list("lt 9.26")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

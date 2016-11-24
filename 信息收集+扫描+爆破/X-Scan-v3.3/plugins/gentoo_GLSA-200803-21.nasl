# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-21.xml
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
 script_id(31447);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-21");
 script_cve_id("CVE-2008-1167", "CVE-2008-1168");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-21
(Sarg: Remote execution of arbitrary code)


    Sarg doesn\'t properly check its input for abnormal content when
    processing Squid log files.
  
Impact

    A remote attacker using a vulnerable Squid as a proxy server or a
    reverse-proxy server can inject arbitrary content into the "User-Agent"
    HTTP client header, that will be processed by sarg, which will lead to
    the execution of arbitrary code, or JavaScript injection, allowing
    Cross-Site Scripting attacks and the theft of credentials.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All sarg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/sarg-2.2.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1167');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1168');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-21] Sarg: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sarg: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/sarg", unaffected: make_list("ge 2.2.5"), vulnerable: make_list("lt 2.2.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

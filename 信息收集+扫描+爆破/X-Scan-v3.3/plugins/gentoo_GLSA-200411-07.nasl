# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-07.xml
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
 script_id(15612);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200411-07");
 script_cve_id("CVE-2004-0992");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-07
(Proxytunnel: Format string vulnerability)


    Florian Schilhabel of the Gentoo Linux Security Audit project found a
    format string vulnerability in Proxytunnel. When the program is started in
    daemon mode (-a [port]), it improperly logs invalid proxy answers to
    syslog.
  
Impact

    A malicious remote server could send specially-crafted invalid answers to
    exploit the format string vulnerability, potentially allowing the execution
    of arbitrary code on the tunnelling host with the rights of the Proxytunnel
    process.
  
Workaround

    You can mitigate the issue by only allowing connections to trusted remote
    servers.
  
');
script_set_attribute(attribute:'solution', value: '
    All Proxytunnel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/proxytunnel-1.2.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0992');
script_set_attribute(attribute: 'see_also', value: 'http://proxytunnel.sourceforge.net/news.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-07] Proxytunnel: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Proxytunnel: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/proxytunnel", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("lt 1.2.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

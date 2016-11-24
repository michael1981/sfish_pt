# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-02.xml
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
 script_id(19364);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200508-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-02
(ProFTPD: Format string vulnerabilities)


     "infamous42md" reported that ProFTPD is vulnerable to format
    string vulnerabilities when displaying a shutdown message containing
    the name of the current directory, and when displaying response
    messages to the client using information retrieved from a database
    using mod_sql.
  
Impact

    A remote attacker could create a directory with a malicious name
    that would trigger the format string issue if specific variables are
    used in the shutdown message, potentially resulting in a Denial of
    Service or the execution of arbitrary code with the rights of the user
    running the ProFTPD server. An attacker with control over the database
    contents could achieve the same result by introducing malicious
    messages that would trigger the other format string issue when used in
    server responses.
  
Workaround

    Do not use the "%C", "%R", or "%U" in shutdown messages, and do
    not set the "SQLShowInfo" directive.
  
');
script_set_attribute(attribute:'solution', value: '
    All ProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/proftpd-1.2.10-r7"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2390');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-02] ProFTPD: Format string vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.2.10-r7"), vulnerable: make_list("lt 1.2.10-r7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

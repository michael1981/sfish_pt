# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-02.xml
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
 script_id(18425);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200506-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-02
(Mailutils: SQL Injection)


    When GNU Mailutils is built with the "mysql" or "postgres" USE
    flag, the sql_escape_string function of the authentication module fails
    to properly escape the "\\" character, rendering it vulnerable to a SQL
    command injection.
  
Impact

    A malicious remote user could exploit this vulnerability to inject
    SQL commands to the underlying database.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Mailutils users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailutils-0.6-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1824');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-02] Mailutils: SQL Injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailutils: SQL Injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/mailutils", unaffected: make_list("ge 0.6-r1"), vulnerable: make_list("lt 0.6-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

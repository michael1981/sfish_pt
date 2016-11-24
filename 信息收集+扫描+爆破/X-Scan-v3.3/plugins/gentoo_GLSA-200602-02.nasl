# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-02.xml
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
 script_id(20873);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200602-02");
 script_cve_id("CVE-2006-0410");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200602-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200602-02
(ADOdb: PostgresSQL command injection)


    Andy Staudacher discovered that ADOdb does not properly sanitize
    all parameters.
  
Impact

    By sending specifically crafted requests to an application that
    uses ADOdb and a PostgreSQL backend, an attacker might exploit the flaw
    to execute arbitrary SQL queries on the host.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ADOdb users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/adodb-4.71"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0410');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200602-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200602-02] ADOdb: PostgresSQL command injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ADOdb: PostgresSQL command injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/adodb", unaffected: make_list("ge 4.71"), vulnerable: make_list("lt 4.71")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-15.xml
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
 script_id(23709);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-15");
 script_cve_id("CVE-2006-1141");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-15
(qmailAdmin: Buffer overflow)


    qmailAdmin fails to properly handle the "PATH_INFO" variable in
    qmailadmin.c. The PATH_INFO is a standard CGI environment variable
    filled with user supplied data.
  
Impact

    A remote attacker could exploit this vulnerability by sending
    qmailAdmin a maliciously crafted URL that could lead to the execution
    of arbitrary code with the permissions of the user running qmailAdmin.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All qmailAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/qmailadmin-1.2.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1141');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-15] qmailAdmin: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'qmailAdmin: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/qmailadmin", unaffected: make_list("ge 1.2.10"), vulnerable: make_list("lt 1.2.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

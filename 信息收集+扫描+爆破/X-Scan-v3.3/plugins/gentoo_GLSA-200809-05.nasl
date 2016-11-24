# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-05.xml
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
 script_id(34104);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200809-05");
 script_cve_id("CVE-2008-2667");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-05
(Courier Authentication Library: SQL injection vulnerability)


    It has been discovered that some input (e.g. the username) passed to
    the library are not properly sanitised before being used in SQL
    queries.
  
Impact

    A remote attacker could provide specially crafted input to the library,
    possibly resulting in the remote execution of arbitrary SQL commands.
    NOTE: Exploitation of this vulnerability requires that a MySQL database
    is used for authentication and that a Non-Latin character set is
    selected.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Courier Authentication Library users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/courier-authlib-0.60.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2667');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-05] Courier Authentication Library: SQL injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Courier Authentication Library: SQL injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/courier-authlib", unaffected: make_list("ge 0.60.6"), vulnerable: make_list("lt 0.60.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

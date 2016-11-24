# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-25.xml
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
 script_id(35912);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-25");
 script_cve_id("CVE-2008-2380");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-25
(Courier Authentication Library: SQL Injection vulnerability)


    It has been reported that some parameters used in SQL queries are not
    properly sanitized before being processed when using a non-Latin locale
    Postgres database.
  
Impact

    A remote attacker could send specially crafted input to an application
    using the library, possibly resulting in the execution of arbitrary SQL
    commands.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Courier Authentication Library users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/courier-authlib-0.62.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2380');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-25] Courier Authentication Library: SQL Injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Courier Authentication Library: SQL Injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/courier-authlib", unaffected: make_list("ge 0.62.2"), vulnerable: make_list("lt 0.62.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-01.xml
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
 script_id(20999);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200603-01");
 script_cve_id("CVE-2006-1012");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-01
(WordPress: SQL injection vulnerability)


    Patrik Karlsson reported that WordPress 1.5.2 makes use of an
    insufficiently filtered User Agent string in SQL queries related to
    comments posting. This vulnerability was already fixed in the
    2.0-series of WordPress.
  
Impact

    An attacker could send a comment with a malicious User Agent
    parameter, resulting in SQL injection and potentially in the subversion
    of the WordPress database. This vulnerability wouldn\'t affect WordPress
    sites which do not allow comments or which require that comments go
    through a moderator.
  
Workaround

    Disable or moderate comments on your WordPress blogs.
  
');
script_set_attribute(attribute:'solution', value: '
    All WordPress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-2.0.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1012');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-01] WordPress: SQL injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: SQL injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 2.0.1"), vulnerable: make_list("le 1.5.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

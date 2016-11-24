# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-11.xml
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
 script_id(30116);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200801-11");
 script_cve_id("CVE-2008-0252");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-11
(CherryPy: Directory traversal vulnerability)


    CherryPy does not sanitize the session id, provided as a cookie value,
    in the FileSession._get_file_path() function before using it as part of
    the file name.
  
Impact

    A remote attacker could exploit this vulnerability to read and possibly
    write arbitrary files on the web server, or to hijack valid sessions,
    by providing a specially crafted session id. This only affects
    applications using file-based sessions.
  
Workaround

    Disable the "FileSession" functionality by using "PostgresqlSession" or
    "RamSession" session management in your CherryPy application.
  
');
script_set_attribute(attribute:'solution', value: '
    All CherryPy 2.2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/cherrypy-2.2.1-r2"
    All CherryPy 3.0 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/cherrypy-3.0.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0252');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-11] CherryPy: Directory traversal vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CherryPy: Directory traversal vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-python/cherrypy", unaffected: make_list("rge 2.2.1-r2", "ge 3.0.2-r1"), vulnerable: make_list("lt 3.0.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

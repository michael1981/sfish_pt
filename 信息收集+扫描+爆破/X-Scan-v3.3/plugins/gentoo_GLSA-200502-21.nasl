# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-21.xml
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
 script_id(16472);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-21");
 script_cve_id("CVE-2005-0453");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-21
(lighttpd: Script source disclosure)


    lighttpd uses file extensions to determine which elements are programs
    that should be executed and which are static pages that should be sent
    as-is. By appending %00 to the filename, you can evade the extension
    detection mechanism while still accessing the file.
  
Impact

    A remote attacker could send specific queries and access the source of
    scripts that should have been executed as CGI or FastCGI applications.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/lighttpd-1.3.10-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://article.gmane.org/gmane.comp.web.lighttpd/1171');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0453');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-21] lighttpd: Script source disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'lighttpd: Script source disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/lighttpd", unaffected: make_list("ge 1.3.10-r1"), vulnerable: make_list("lt 1.3.10-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-16.xml
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
 script_id(26214);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200709-16");
 script_cve_id("CVE-2007-4727");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-16
(Lighttpd: Buffer overflow)


    Mattias Bengtsson and Philip Olausson have discovered a buffer overflow
    vulnerability in the function fcgi_env_add() in the file mod_fastcgi.c
    when processing overly long HTTP headers.
  
Impact

    A remote attacker could send a specially crafted request to the
    vulnerable Lighttpd server, resulting in the remote execution of
    arbitrary code with privileges of the user running the web server. Note
    that mod_fastcgi is disabled in Gentoo\'s default configuration.
  
Workaround

    Edit the file /etc/lighttpd/lighttpd.conf and comment the following
    line: "include mod_fastcgi.conf"
  
');
script_set_attribute(attribute:'solution', value: '
    All Lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/lighttpd-1.4.18"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4727');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-16] Lighttpd: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Lighttpd: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/lighttpd", unaffected: make_list("ge 1.4.18"), vulnerable: make_list("lt 1.4.18")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-04.xml
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
 script_id(14455);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200403-04");
 script_cve_id("CVE-2004-0113");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-04
(Multiple security vulnerabilities in Apache 2)


    Three vulnerabilities were found:
    A memory leak in ssl_engine_io.c for mod_ssl in Apache 2.0.48 and below
    allows remote attackers to cause a denial of service attack via plain
    HTTP requests to the SSL port of an SSL-enabled server.
    Apache fails to filter terminal escape sequences from error logs that
    begin with the ASCII (0x1B) sequence and are followed by a  series of
    arguments. If a remote attacker could inject escape sequences into an
    Apache error log, the attacker could take advantages of weaknesses in
    various terminal emulators, launching attacks against remote users
    including further denial of service attacks, file modification, and the
    execution of arbitrary commands.
    The Apache mod_disk_cache has been found to be vulnerable to a weakness
    that allows attackers to gain access to authentication credentials
    through the issue of caching HTTP hop-by-hop headers which would
    contain plaintext user passwords. There is no available resolution for
    this issue yet.
  
Impact

    No special privileges are required for these vulnerabilities. As a
    result, all users are recommended to upgrade their Apache
    installations.
  
Workaround

    There is no immediate workaround; a software upgrade is required. There
    is no workaround for the mod_disk_cache issue; users are recommended to
    disable the feature on their servers until a patched version is
    released.
  
');
script_set_attribute(attribute:'solution', value: '
    Users are urged to upgrade to Apache 2.0.49:
    # emerge sync
    # emerge -pv ">=www-servers/apache-2.0.49"
    # emerge ">=www-servers/apache-2.0.49"
    # ** IMPORTANT **
    # If you are migrating from Apache 2.0.48-r1 or earlier versions,
    # it is important that the following directories are removed.
    # The following commands should cause no data loss since these
    # are symbolic links.
    # rm /etc/apache2/lib /etc/apache2/logs /etc/apache2/modules
    # rm /etc/apache2/modules
    # ** ** ** ** **
    # ** ALSO NOTE **
    # Users who use mod_disk_cache should edit their Apache
    # configuration and disable mod_disk_cache.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/9933/info/');
script_set_attribute(attribute: 'see_also', value: 'http://www.apache.org/dist/httpd/Announcement2.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0113');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-04] Multiple security vulnerabilities in Apache 2');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple security vulnerabilities in Apache 2');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("eq 1.3*", "ge 2.0.49"), vulnerable: make_list("le 2.0.48")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

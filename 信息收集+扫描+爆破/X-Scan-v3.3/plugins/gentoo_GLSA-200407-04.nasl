# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-04.xml
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
 script_id(14537);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200407-04");
 script_cve_id("CVE-2004-0656");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-04
(Pure-FTPd: Potential DoS when maximum connections is reached)


    Pure-FTPd contains a bug in the accept_client function handling the
    setup of new connections.
  
Impact

    When the maximum number of connections is reached an attacker could
    exploit this vulnerability to perform a Denial of Service attack.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pure-FTPd users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-ftp/pure-ftpd-1.0.18-r1"
    # emerge ">=net-ftp/pure-ftpd-1.0.18-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.pureftpd.org');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0656');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-04] Pure-FTPd: Potential DoS when maximum connections is reached');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pure-FTPd: Potential DoS when maximum connections is reached');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/pure-ftpd", unaffected: make_list("ge 1.0.18-r1"), vulnerable: make_list("le 1.0.18")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

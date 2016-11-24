# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-13.xml
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
 script_id(21355);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200605-13");
 script_cve_id("CVE-2006-1516", "CVE-2006-1517");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200605-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200605-13
(MySQL: Information leakage)


    The processing of the COM_TABLE_DUMP command by a MySQL server fails to
    properly validate packets that arrive from the client via a network
    socket.
  
Impact

    By crafting specific malicious packets an attacker could gather
    confidential information from the memory of a MySQL server process, for
    example results of queries by other users or applications. By using PHP
    code injection or similar techniques it would be possible to exploit
    this flaw through web applications that use MySQL as a database
    backend.
    Note that on 5.x versions it is possible to overwrite the stack and
    execute arbitrary code with this technique. Users of MySQL 5.x are
    urged to upgrade to the latest available version.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version.
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-4.0.27"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2006-05/msg00041.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1516');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1517');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200605-13] MySQL: Information leakage');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Information leakage');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.1.19", "rge 4.0.27"), vulnerable: make_list("lt 4.1.19")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

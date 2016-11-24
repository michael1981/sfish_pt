# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-09.xml
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
 script_id(14495);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-09");
 script_cve_id("CVE-2004-0432");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-09
(ProFTPD Access Control List bypass vulnerability)


    ProFTPD 1.2.9 introduced a vulnerability that allows CIDR-based ACLs (such
    as 10.0.0.1/24) to be bypassed. The CIDR ACLs are disregarded, with the net
    effect being similar to an "AllowAll" directive.
  
Impact

    This vulnerability may allow unauthorized files, including critical system
    files to be downloaded and/or modified, thereby allowing a potential remote
    compromise of the server.
  
Workaround

    Users may work around the problem by avoiding use of CIDR-based ACLs.
  
');
script_set_attribute(attribute:'solution', value: '
    ProFTPD users are encouraged to upgrade to the latest version of the
    package:
    # emerge sync
    # emerge -pv ">=net-ftp/proftpd-1.2.9-r2"
    # emerge ">=net-ftp/proftpd-1.2.9-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0432');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-09] ProFTPD Access Control List bypass vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD Access Control List bypass vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.2.9-r2"), vulnerable: make_list("eq 1.2.9-r1", "eq 1.2.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

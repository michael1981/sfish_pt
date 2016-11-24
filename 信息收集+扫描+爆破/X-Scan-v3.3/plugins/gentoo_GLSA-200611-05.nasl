# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-05.xml
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
 script_id(23670);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200611-05");
 script_cve_id("CVE-2006-5778");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-05
(Netkit FTP Server: Privilege escalation)


    Paul Szabo reported that an incorrect seteuid() call after the chdir()
    function can allow an attacker to access a normally forbidden
    directory, in some very particular circumstances, for example when the
    NFS-hosted targetted directory is not reachable by the client-side root
    user. Additionally, some potentially exploitable unchecked setuid()
    calls were also fixed.
  
Impact

    A local attacker might craft his home directory to gain access through
    ftpd to normally forbidden directories like /root, possibly with
    writing permissions if seteuid() fails and if the ftpd configuration
    allows that. The unchecked setuid() calls could also lead to a root FTP
    login, depending on the FTP server configuration.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Netkit FTP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/netkit-ftpd-0.17-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5778');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-05] Netkit FTP Server: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Netkit FTP Server: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/netkit-ftpd", unaffected: make_list("ge 0.17-r4"), vulnerable: make_list("lt 0.17-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

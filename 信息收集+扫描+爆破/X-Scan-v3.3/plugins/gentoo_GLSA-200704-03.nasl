# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-03.xml
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
 script_id(24936);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200704-03");
 script_cve_id("CVE-2007-1507");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-03
(OpenAFS: Privilege escalation)


    Benjamin Bennett discovered that the OpenAFS client contains a design
    flaw where cache managers do not use authenticated server connections
    when performing actions not requested by a user.
  
Impact

    If setuid is enabled on the client cells, an attacker can supply a fake
    FetchStatus reply that sets setuid and root ownership of a file being
    executed. This could provide root access on the client. Remote attacks
    may be possible if an attacker can entice a user to execute a known
    file. Note that setuid is enabled by default in versions of OpenAFS
    prior to 1.4.4.
  
Workaround

    Disable the setuid functionality on all client cells. This is now the
    default configuration in OpenAFS.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenAFS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/openafs-1.4.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1507');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-03] OpenAFS: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenAFS: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/openafs", unaffected: make_list("ge 1.4.4"), vulnerable: make_list("lt 1.4.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

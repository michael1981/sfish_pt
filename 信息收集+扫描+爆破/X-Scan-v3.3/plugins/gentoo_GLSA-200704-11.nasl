# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-11.xml
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
 script_id(25056);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200704-11");
 script_cve_id("CVE-2007-1856");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-11
(Vixie Cron: Denial of Service)


    During an internal audit, Raphael Marichez of the Gentoo Linux Security
    Team found that Vixie Cron has weak permissions set on Gentoo, allowing
    for a local user to create hard links to system and users cron files,
    while a st_nlink check in database.c will generate a superfluous error.
  
Impact

    Depending on the partitioning scheme and the "cron" group membership, a
    malicious local user can create hard links to system or users cron
    files that will trigger the st_link safety check and prevent the
    targeted cron file from being run from the next restart or database
    reload.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Vixie Cron users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-process/vixie-cron-4.1-r10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1856');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-11] Vixie Cron: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Vixie Cron: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-process/vixie-cron", unaffected: make_list("ge 4.1-r10"), vulnerable: make_list("lt 4.1-r10")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
